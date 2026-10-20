import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { applyParams, runApiSteps, runSteps } from '../core/plan.js';
import { Ctx } from '../core/ctx.js';
import { isPersonalDevice, matchNode, matchPeer, nodeState, tailscalePeers } from '../core/panel.js';
import { tsCreateAuthKey, tsDeleteDevice } from '../core/tailscale.js';
import { run, writeTools } from './helpers.js';

const ago = (iso?: string) => {
    if (!iso) return undefined;
    const m = Math.round((Date.now() - Date.parse(iso)) / 60_000);
    return m < 2 ? 'now' : m < 120 ? `${m}m` : m < 48 * 60 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`;
};

export function registerTailnetTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'tailnet_devices',
        'Every device of the tailnet (Tailscale API with TAILSCALE_API_KEY, else this machine\'s `tailscale status`): online / last seen, OS and client version, update available, node key expiry, tags — and which inventory host and panel node it is.',
        {
            filter: z.string().optional().describe('substring of the name / hostname / OS / tag'),
            offlineDays: z.number().int().optional().describe('only devices offline for at least this many days'),
        },
        ({ filter, offlineDays }) =>
            run(async () => {
                const inv = ctx.inventory();
                const [peers, nodes] = await Promise.all([tailscalePeers(ctx.config), ctx.panelNodes()]);
                const hosts = [...inv.hosts.values()];
                let rows = peers.map((p) => {
                    const h = hosts.find((x) => matchPeer(x, [p]));
                    const n = h && nodes ? matchNode(h, nodes) : undefined;
                    return {
                        device: p.dnsName.split('.')[0] || p.hostName,
                        online: p.online ? 'yes' : `no, ${ago(p.lastSeen) ?? '?'}`,
                        ip: p.ips.find((i) => i.includes('.')),
                        os: [p.os, p.clientVersion].filter(Boolean).join(' ') || undefined,
                        update: p.updateAvailable ? 'available' : undefined,
                        key: p.keyDaysLeft === undefined ? undefined : p.keyDaysLeft < 0 ? 'EXPIRED' : `${p.keyDaysLeft}d`,
                        tags: p.tags?.join(',') || undefined,
                        host: h ? `${h.name}${h.disabled ? ' (disabled)' : ''}` : undefined,
                        panel: n ? `${n.name} ${nodeState(n)}` : undefined,
                        self: p.self || undefined,
                        offlineDays: p.online || !p.lastSeen ? 0 : Math.floor((Date.now() - Date.parse(p.lastSeen)) / 86_400_000),
                    };
                });
                if (filter) {
                    const f = filter.toLowerCase();
                    rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(f));
                }
                if (offlineDays !== undefined) rows = rows.filter((r) => r.offlineDays >= offlineDays);
                rows.sort((a, b) => a.device.localeCompare(b.device));
                return {
                    source: ctx.config.tailscaleApi ? 'Tailscale API' : 'local tailscale status (set TAILSCALE_API_KEY for every device, key expiry, updates)',
                    devices: rows.length,
                    online: rows.filter((r) => r.online === 'yes').length,
                    notInInventory: rows.filter((r) => !r.host && !isPersonalDevice({ os: r.os?.split(' ')[0] })).length,
                    keysExpiringSoon: rows.filter((r) => r.key && (r.key === 'EXPIRED' || parseInt(r.key) < 30)).map((r) => `${r.device} ${r.key}`),
                    rows: rows.map(({ offlineDays: _o, ...r }) => r),
                };
            }),
    );

    writeTools(() => {
        server.tool(
            'tailnet_device_remove',
            'Remove a machine from the tailnet (Tailscale API, needs TAILSCALE_API_KEY): the last step of taking a server out of service. The dry run shows the device, when it was last seen and whether it is still in fleet.yaml; an online device or one still in the inventory is refused unless force.',
            {
                device: z.string().describe('MagicDNS name (node-pl2), full name or hostname'),
                force: z.boolean().default(false).describe('remove even if it is online or still an enabled inventory host'),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'tailnet_device_remove', args, args, async () => {
                        const api = ctx.config.tailscaleApi;
                        if (!api) throw new Error('needs TAILSCALE_API_KEY (mia secrets set TAILSCALE_API_KEY)');
                        const want = args.device.toLowerCase();
                        const peers = await tailscalePeers(ctx.config);
                        const hits = peers.filter((p) => p.dnsName.toLowerCase() === want || p.dnsName.toLowerCase().split('.')[0] === want || p.hostName.toLowerCase() === want);
                        if (!hits.length) throw new Error(`no tailnet device "${args.device}"`);
                        if (hits.length > 1) throw new Error(`"${args.device}" matches ${hits.length} devices: ${hits.map((h) => h.dnsName).join(', ')} — use the full name`);
                        const p = hits[0];
                        const h = [...ctx.inventory().hosts.values()].find((x) => matchPeer(x, [p]));
                        const blockers: string[] = [];
                        if (!args.force && p.online) blockers.push('the device is online — take it out of service first, or force');
                        if (!args.force && h && !h.disabled) blockers.push(`still an enabled inventory host (${h.name}) — disable/remove it in fleet.yaml first (fleet_host_edit), or force`);
                        if (p.self) blockers.push('this is the machine mia runs on');
                        return [
                            {
                                target: `tailnet ${p.dnsName}`,
                                action: 'delete the device from the tailnet',
                                // lastSeen of an online device moves every few seconds — keeping it would change planHash between dry-run and apply
                                before: { online: p.online, lastSeen: p.online ? undefined : p.lastSeen, os: p.os, ip: p.ips[0], inventory: h ? `${h.name}${h.disabled ? ' (disabled)' : ''}` : 'not in fleet.yaml' },
                                blockers,
                                apply: () => tsDeleteDevice(api, p.id!),
                                verify: async () => ((await tailscalePeers(ctx.config)).some((x) => x.id === p.id) ? 'still listed' : true),
                            },
                        ];
                    }),
                ),
        );
    });

    writeTools(() => {
        server.tool(
            'tailnet_join',
            'Join a server to the tailnet over its public address (hosts.<name>.bootstrap in fleet.yaml): for a machine that is already set up but logged out of Tailscale or never joined. The key is a fresh one-time key from the Tailscale API (TAILSCALE_API_KEY), made only on apply and passed through the environment — never in the plan or journal; without the API it falls back to TAILSCALE_AUTH_KEY. Runs `tailscale up --reset --ssh --hostname node-<name>` (+ exit node like the fleet), then verifies the node shows up online.',
            {
                host: z.string().describe('inventory host with bootstrap.address'),
                sshUser: z.string().optional().describe('ssh user on the public address (default: bootstrap.user, else root)'),
                sshPort: z.number().int().optional(),
                exitNode: z.boolean().default(true).describe('--advertise-exit-node, as every fleet node does'),
                install: z.boolean().default(false).describe('install Tailscale first when it is missing (official install script), for a fresh server set up without node_bootstrap'),
                ...applyParams,
            },
            (args) =>
                run(async () => {
                    const h = ctx.inventory().get(args.host);
                    const address = h.bootstrap?.address;
                    if (!address) throw new Error(`hosts.${args.host}.bootstrap.address is not set in fleet.yaml`);
                    const via = { address, user: args.sshUser ?? h.bootstrap?.user ?? 'root', port: args.sshPort ?? h.bootstrap?.port ?? 22, ...(h.bootstrap?.identityFile && address === h.bootstrap.address ? { identityFile: h.bootstrap.identityFile } : {}) };
                    const hostname = /^\d+\.\d+\.\d+\.\d+$/.test(h.address) || h.address.includes('.') ? `node-${h.name}` : h.address;
                    return runSteps(ctx, 'tailnet_join', args, { ...args, defaultBatch: 1 }, async () => {
                        const blockers: string[] = [];
                        const ask = 'command -v tailscale >/dev/null && tailscale status --json 2>/dev/null | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get(\'BackendState\'),(d.get(\'Self\') or {}).get(\'HostName\',\'\'))" || echo NO_TAILSCALE';
                        // already in the tailnet (public ssh is usually closed by then): nothing to do
                        const over = await ctx.transport.exec(h, ask, { timeoutMs: 15_000 });
                        const probe = over.ok && over.stdout.trim().startsWith('Running') ? over : await ctx.transport.exec(h, ask, { via, timeoutMs: 30_000 });
                        if (!probe.ok) blockers.push(`cannot ssh ${via.user}@${address}: ${probe.error ?? probe.stderr}`);
                        const state = probe.stdout.trim();
                        const install = state.includes('NO_TAILSCALE');
                        if (install && !args.install) blockers.push('tailscale is not installed there (node_bootstrap installs it, or install:true)');
                        const api = ctx.config.tailscaleApi;
                        if (!api && !process.env.TAILSCALE_AUTH_KEY) blockers.push('needs TAILSCALE_API_KEY (one-time keys) or TAILSCALE_AUTH_KEY');
                        let key = '';
                        if (args.apply && !blockers.length && !state.startsWith('Running')) key = api ? await tsCreateAuthKey(api, `mia tailnet_join ${hostname}`) : (process.env.TAILSCALE_AUTH_KEY ?? '');
                        const flags = ['--reset', '--ssh', `--hostname=${hostname}`, ...(args.exitNode ? ['--advertise-exit-node'] : []), '--timeout=60s'];
                        return [
                            {
                                host: h,
                                via,
                                action: `${install ? 'install Tailscale (tailscale.com/install.sh), then ' : ''}tailscale up ${flags.join(' ')} (one-time key${api ? ' from the Tailscale API' : ': TAILSCALE_AUTH_KEY'})`,
                                script: `${install ? 'command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1; systemctl enable --now tailscaled >/dev/null 2>&1\n' : ''}tailscale up ${flags.join(' ')} --authkey="$TS_AUTHKEY" 2>&1 | sed 's/tskey-[A-Za-z0-9-]*/«redacted»/g'; tailscale ip -4`,
                                env: { TS_AUTHKEY: key },
                                timeoutMs: 120_000,
                                preview: { ssh: `${via.user}@${address}:${via.port}`, tailscale: state || 'unknown' },
                                ...(state.startsWith('Running') ? { noop: `already in the tailnet (${state})` } : {}),
                                blockers,
                                verify: async (res) => (/^100\.\d+\.\d+\.\d+/m.test(res.stdout) ? true : `no tailnet address after tailscale up: ${res.stdout.slice(-200)}`),
                            },
                        ];
                    });
                }),
        );
    });
}
