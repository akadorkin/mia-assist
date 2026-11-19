import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { hzCreate, hzDelete, hzServerByName, hzSnapshot, hzSnapshots, hzSshKeys, waitPort } from '../core/hetzner.js';
import { tsCreateAuthKey } from '../core/tailscale.js';
import { ApiStep, applyParams, runApiSteps, waitFor } from '../core/plan.js';
import { run, writeTools } from './helpers.js';

function token(ctx: Ctx): string {
    if (!ctx.config.hetznerToken) throw new Error('needs HETZNER_API_TOKEN (mia secrets set HETZNER_API_TOKEN)');
    return ctx.config.hetznerToken;
}

/** This machine's public key: mia reaches a fresh server over public ssh with it. */
function localPub(): { name: string; key: string } | undefined {
    for (const f of ['id_ed25519.pub', 'id_rsa.pub']) {
        const p = path.join(os.homedir(), '.ssh', f);
        if (fs.existsSync(p)) return { name: `mia-${os.hostname()}`, key: fs.readFileSync(p, 'utf8') };
    }
    return undefined;
}

/**
 * Hetzner hands a released address to the next server: the host key remembered for it belongs to a machine that is gone
 * (a new server got the address of a deleted one and bootstrap stopped on «host key changed»). Forget it —
 * when a server is bought (its key is new by definition) and when one is deleted.
 */
export function forgetHostKey(address: string | undefined): void {
    if (!address) return;
    try {
        execFileSync('ssh-keygen', ['-R', address], { stdio: 'ignore' });
    } catch {
        /* no known_hosts or no such entry */
    }
}

/** cloud-init user-data of a server made from a prepared node image: its own name, then into the tailnet the way bootstrap does it. */
export function firstBootJoin(hostname: string, authKey: string): string {
    return ['#cloud-config', 'runcmd:', `  - [ sh, -c, "hostnamectl set-hostname ${hostname}; systemctl enable --now tailscaled; tailscale up --ssh --advertise-exit-node --hostname=${hostname} --authkey=${authKey}" ]`, ''].join('\n');
}

export function registerHetznerTools(server: McpServer, ctx: Ctx) {
    server.tool('hetzner_server', 'A Hetzner Cloud server by name (HETZNER_API_TOKEN): id, type, location, addresses, status — or null when there is none.', { name: z.string() }, ({ name }) =>
        run(async () => ({ server: (await hzServerByName(token(ctx), name)) ?? null })),
    );

    writeTools(() => {
        server.tool(
            'hetzner_server_create',
            'Buy a Hetzner Cloud server: the first server type × location pair that is in stock, in the given order (resource_unavailable → next pair), with the named ssh keys plus this machine\'s own public key (registered in the project when missing). Waits until the server runs and sshd answers. A server with this name already there is left as is. Costs money from the first hour. image «label:<selector>» = the newest snapshot with that label (e.g. a prepared node image: everything installed, no identity); with tailnetHostname the server joins the tailnet on first boot (a one-time key minted on apply travels in cloud-init user-data, never in the plan) — such an image keeps public ssh closed.',
            {
                name: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).describe('server name, e.g. node-de1'),
                types: z.array(z.string()).min(1).default(['cx43', 'cx33', 'cx23']).describe('server types, most wanted first'),
                locations: z.array(z.string()).min(1).default(['nbg1', 'fsn1', 'hel1']),
                image: z.string().default('ubuntu-24.04').describe('image name, a snapshot id, or label:<selector> for the newest snapshot with that label'),
                tailnetHostname: z.string().regex(/^[a-z0-9-]+$/).optional().describe('join the tailnet on first boot under this name (tag:edge, Tailscale SSH): for images without public ssh'),
                sshKeys: z.array(z.string()).default([]).describe('names of ssh keys in the Hetzner project'),
                labels: z.record(z.string()).default({ fleet: 'mia', role: 'exit' }),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'hetzner_server_create', args, args, async () => {
                        const t = token(ctx);
                        const have = await hzServerByName(t, args.name);
                        if (have) return [{ target: `server ${args.name}`, action: '-', noop: `already there: #${have.id} ${have.type} ${have.location} ${have.ipv4}`, apply: async () => undefined }];
                        const pub = localPub();
                        const keys = await hzSshKeys(t, args.sshKeys, pub);
                        const blockers = [...(keys.missing.length ? [`no such ssh key in the project: ${keys.missing.join(', ')}`] : []), ...(!pub ? ['no ~/.ssh/id_ed25519.pub on this machine: mia could not log in to the new server'] : [])];
                        let image: string | number = /^\d+$/.test(args.image) ? Number(args.image) : args.image;
                        let imageInfo = args.image;
                        if (args.image.startsWith('label:')) {
                            const snap = (await hzSnapshots(t, args.image.slice(6)))[0];
                            if (!snap) blockers.push(`no snapshot with label ${args.image.slice(6)}: make such a snapshot first (hetzner_snapshot_create with labels)`);
                            else [image, imageInfo] = [snap.id, `snapshot #${snap.id} «${snap.description}» of ${snap.created.slice(0, 10)}`];
                        }
                        if (args.tailnetHostname && !ctx.config.tailscaleApi) blockers.push('tailnetHostname needs TAILSCALE_API_KEY: the one-time key for the first boot is minted through the API');
                        const step: ApiStep = {
                            target: `server ${args.name}`,
                            action: `create ${args.types.join(' → ')} in ${args.locations.join(' → ')}, ${imageInfo}, keys ${[...args.sshKeys, ...(pub ? [pub.name] : [])].join(', ')}${args.tailnetHostname ? `, joins the tailnet as ${args.tailnetHostname} on first boot` : ''}`,
                            warnings: keys.toRegister ? [`this machine's public key is not in the project yet: it is added as ${keys.toRegister}`] : undefined,
                            blockers: blockers.length ? blockers : undefined,
                            apply: async () => {
                                const ids = (await hzSshKeys(t, args.sshKeys, pub, true)).ids;
                                const userData = args.tailnetHostname ? firstBootJoin(args.tailnetHostname, await tsCreateAuthKey(ctx.config.tailscaleApi!, `mia image ${args.tailnetHostname}`, ['tag:edge'])) : undefined;
                                const s = await hzCreate(t, { name: args.name, types: args.types, locations: args.locations, image, sshKeys: ids, labels: args.labels, userData });
                                forgetHostKey(s.ipv4);
                                // an image that joins the tailnet by itself keeps public ssh closed: readiness is the tailnet, not port 22
                                return { ...s, ssh: args.tailnetHostname ? true : !!s.ipv4 && (await waitPort(s.ipv4, 22, 120_000)) };
                            },
                            verify: async () => {
                                const s = await hzServerByName(t, args.name);
                                return s?.status === 'running' ? true : `server is ${s?.status ?? 'missing'}`;
                            },
                        };
                        return [step];
                    }),
                ),
        );

        server.tool(
            'hetzner_snapshot_create',
            'Snapshot of a Hetzner Cloud server (a few minutes; billed per GB and month). With labels it can be picked later as image «label:<selector>» for new servers — make it only from a server with its identity removed (tailnet key, certificates, registrations) and powered off.',
            {
                server: z.string().describe('server name'),
                description: z.string().min(3),
                labels: z.record(z.string()).default({}),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'hetzner_snapshot_create', args, args, async () => {
                        const t = token(ctx);
                        const s = await hzServerByName(t, args.server);
                        if (!s) return [{ target: `server ${args.server}`, action: '-', blockers: ['no such server in the project'], apply: async () => undefined }];
                        return [
                            {
                                target: `server ${s.name} #${s.id}`,
                                action: `snapshot «${args.description}»${Object.keys(args.labels).length ? ` labels ${JSON.stringify(args.labels)}` : ''}`,
                                before: { status: s.status, type: s.type },
                                warnings: s.status !== 'off' ? ['the server is running: a snapshot of a live disk may catch files half-written — power it off first'] : undefined,
                                apply: () => hzSnapshot(t, s.id, args.description, args.labels),
                            },
                        ];
                    }),
                ),
        );

        server.tool(
            'hetzner_server_delete',
            'Delete a Hetzner Cloud server by name: irreversible, its disk and addresses are gone and billing stops. Only on the owner\'s explicit word for this server.',
            { name: z.string(), ...applyParams },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'hetzner_server_delete', args, args, async () => {
                        const t = token(ctx);
                        const s = await hzServerByName(t, args.name);
                        if (!s) return [{ target: `server ${args.name}`, action: '-', noop: 'no such server in the project', apply: async () => undefined }];
                        return [
                            {
                                target: `server ${s.name} #${s.id}`,
                                action: 'delete (irreversible)',
                                before: { type: s.type, location: s.location, ipv4: s.ipv4, status: s.status },
                                apply: async () => {
                                    await hzDelete(t, s.id);
                                    forgetHostKey(s.ipv4);
                                },
                                // deletion is an action on Hetzner's side: the server stays listed for a few seconds
                                verify: () => waitFor(async () => ((await hzServerByName(t, args.name)) ? 'still there' : true), 60_000, 3000),
                            },
                        ];
                    }),
                ),
        );
    });
}
