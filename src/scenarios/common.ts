import dns from 'node:dns/promises';
export { addToGroup, flowStyle, groupsOf, removeFromGroups } from '../core/fleetfile.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { tailscalePeers, matchPeer } from '../core/panel.js';
import { RunVars, StepDef } from '../core/scenario.js';
import { ruProbe } from '../tools/ruprobe.js';

export const list = (v: unknown): string[] =>
    Array.isArray(v) ? v.map(String) : typeof v === 'string' ? v.split(',').map((s) => s.trim()).filter(Boolean) : [];

/** Comma-separated list parameter ("a,b" on the console, an array over MCP). */
export const listParam = (about: string) => z.union([z.array(z.string()), z.string()]).optional().describe(about);

export const today = () => new Date().toISOString().slice(0, 10);

/**
 * `git commit` with the configured author (MIA_GIT_AUTHOR), so a checkout without user.name still commits.
 * Nothing staged is ok: a retry after a failed push must reach the push instead of dying on «nothing to commit».
 */
export function gitCommit(ctx: Ctx, message: string): string[] {
    const a = ctx.config.gitAuthor;
    const git = [...(a ? ['-c', `user.name=${a.name}`, '-c', `user.email=${a.email}`] : []), 'commit', '-m', message];
    return ['sh', '-c', 'git diff --cached --quiet || exec git "$@"', 'sh', ...git];
}

/** Resolve through public resolvers (Cloudflare first), not the local cache: that one lies right after a change. */
export async function resolveA(name: string): Promise<string[]> {
    const r = new dns.Resolver({ timeout: 4000, tries: 2 });
    r.setServers(['1.1.1.1', '8.8.8.8']);
    return r.resolve4(name).catch(() => dns.resolve4(name).catch(() => [] as string[]));
}

/**
 * A records straight from the zone's authoritative name servers. Public resolvers cache the «no such name»
 * answer of a record that did not exist yet for the zone's negative TTL (Cloudflare: up to 30 min) — a
 * freshly created record can stay «no A record» on 1.1.1.1 long after the provider serves it.
 */
export async function resolveAuthA(name: string): Promise<string[]> {
    const labels = name.replace(/\.$/, '').split('.');
    for (let i = 1; i < labels.length - 1; i++) {
        const zone = labels.slice(i).join('.');
        const ns = await dns.resolveNs(zone).catch(() => [] as string[]);
        if (!ns.length) continue;
        const ips = (await Promise.all(ns.slice(0, 3).map((n) => dns.resolve4(n).catch(() => [] as string[])))).flat();
        if (!ips.length) break;
        const r = new dns.Resolver({ timeout: 4000, tries: 2 });
        r.setServers(ips.slice(0, 3));
        return r.resolve4(name).catch(() => [] as string[]);
    }
    return resolveA(name);
}

/** A record check: the domain must resolve to the address (certbot HTTP-01, clients). */
export function dnsStep(id: string, domain: (r: RunVars) => string[], ip: (r: RunVars) => string, pollSec = 0): StepDef {
    return {
        id,
        title: 'DNS: A records point to the new address',
        kind: 'check',
        run: async (_ctx, r) => {
            const out: Record<string, string> = {};
            for (const d of domain(r)) out[d] = (await resolveAuthA(d)).join(',') || 'no A record';
            return out;
        },
        expect: (data: Record<string, string>, r) => {
            const bad = Object.entries(data).filter(([, a]) => !a.split(',').includes(ip(r)));
            return bad.length ? `not ${ip(r)} yet: ${bad.map(([d, a]) => `${d} → ${a}`).join('; ')}. Change the A records (Cloudflare), wait for the TTL, then retry.` : true;
        },
        ...(pollSec ? { poll: { timeoutSec: pollSec, everySec: 30 } } : {}),
    };
}

/** Tailscale IPv4 and MagicDNS name of an inventory host, from this machine's `tailscale status`. */
export async function tailnetOf(ctx: Ctx, name: string): Promise<{ ip?: string; fqdn?: string; online?: boolean }> {
    const h = ctx.inventory().get(name);
    const peers = await tailscalePeers(ctx.config).catch(() => []);
    const p = matchPeer(h, peers);
    return { ip: p?.ips.find((ip) => ip.includes('.')) ?? (/^100\.\d+\.\d+\.\d+$/.test(h.address) ? h.address : undefined), fqdn: p?.dnsName || undefined, online: p?.online };
}

export async function tailnetIp(ctx: Ctx, name: string): Promise<string | undefined> {
    return (await tailnetOf(ctx, name)).ip;
}

/** Local checkout of one of the owner's repos (MIA_REPOS), or a clear error the step shows. */
export function repoDir(ctx: Ctx, name: string): string {
    const dir = ctx.config.repos[name];
    if (!dir) throw new Error(`repo "${name}" is not configured: MIA_REPOS="${name}=/path/to/checkout,…" (have: ${Object.keys(ctx.config.repos).join(', ') || 'none'})`);
    return dir;
}

/** Public IPv4 of an inventory host: bootstrap address, else its domain's A record. */
export async function publicIp(ctx: Ctx, name: string): Promise<string | undefined> {
    const h = ctx.inventory().get(name);
    if (h.bootstrap?.address && /^\d+\.\d+\.\d+\.\d+$/.test(h.bootstrap.address)) return h.bootstrap.address;
    if (h.domain) return (await resolveA(h.domain))[0];
    return undefined;
}

/** mcp-remnawave nodes_list rows. */
export interface PanelRow {
    name: string;
    uuid: string;
    state: string;
    profile: string | null;
    usersOnline?: number;
    address?: string;
}

export const rowsOf = (data: unknown): PanelRow[] => ((data as { nodes?: PanelRow[] })?.nodes ?? []) as PanelRow[];

/** "old=new,old2=new2" on the console, or an object over MCP. */
export const mapParam = (about: string) => z.union([z.string(), z.record(z.string())]).optional().describe(about);

export function toMap(v: unknown): Record<string, string> {
    if (!v) return {};
    if (typeof v === 'object') return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, String(x)]));
    return Object.fromEntries(
        String(v)
            .split(',')
            .map((p) => p.trim())
            .filter(Boolean)
            .map((p) => {
                const i = p.indexOf('=');
                if (i <= 0) throw new Error(`«${p}» не в виде старое=новое`);
                return [p.slice(0, i).trim(), p.slice(i + 1).trim()];
            }),
    );
}

/**
 * Gate: the targets must pass from the censored side through every ISP of the vantage host (ru_probe). blocked-ru / down stop the run.
 * `watch` re-probes every 2 min for that many minutes — DPI has been seen cutting a fresh address 9–15 min after a DNS switch.
 */
export function ruGateStep(id: string, title: string, targets: (r: RunVars) => string[], o: { watchMin?: number; rollback?: (r: RunVars) => string; gate?: boolean } = {}): StepDef {
    return {
        id,
        title,
        kind: 'check',
        gate: o.gate ?? true,
        run: async (ctx, r) => {
            const rounds = Math.max(1, Math.round((o.watchMin ?? 0) / 2) + (o.watchMin ? 1 : 0));
            const history: Array<{ at: string; results: Record<string, { verdict: string; note: string }> }> = [];
            for (let i = 0; i < rounds; i++) {
                if (i) await new Promise((ok) => setTimeout(ok, 120_000));
                const res = await ruProbe(ctx, { to: targets(r) });
                history.push({ at: new Date().toISOString().slice(11, 19), results: res.results });
                if (Object.values(res.results).some((x) => x.verdict === 'blocked-ru' || x.verdict === 'down')) break;
            }
            return history;
        },
        expect: (d: Array<{ results: Record<string, { verdict: string; note: string }> }>, r) => {
            const last = d[d.length - 1]?.results ?? {};
            const bad = Object.entries(last).filter(([, x]) => x.verdict === 'blocked-ru' || x.verdict === 'down');
            if (!bad.length) return true;
            return `${bad.map(([t, x]) => `${t}: ${x.note}`).join('\n')}${o.rollback ? `\nОткат: ${o.rollback(r)}` : ''}\n«пропустить» = к шагу отката (если он есть), дальше ранбук остановится`;
        },
    };
}
