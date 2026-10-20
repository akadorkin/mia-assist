import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { run } from './helpers.js';

/**
 * ru_probe: is an address reachable from inside a censored network: from a vantage host with one
 * interface per local ISP (MIA_PROBE_FROM, MIA_PROBE_IFACES) with the address forced (--resolve),
 * plus a control from a datacenter host (MIA_PROBE_CONTROL). Both ISPs failing while the datacenter passes = DPI (TSPU) blocks the
 * address:port on the way — roll the DNS back first, analyse later. Read-only: one TLS handshake per pair.
 */

export interface ProbeTarget {
    ip: string;
    port: number;
    sni: string;
}

/** "ip:port" or "ip:port/sni" (default port 443, default sni = the ip). */
export function parseTarget(s: string, defaultSni?: string): ProbeTarget {
    const m = s.trim().match(/^([\w.-]+)(?::(\d{1,5}))?(?:\/([\w.-]+))?$/);
    if (!m) throw new Error(`цель «${s}»: нужно ip:port или ip:port/sni`);
    return { ip: m[1], port: m[2] ? Number(m[2]) : 443, sni: m[3] ?? defaultSni ?? m[1] };
}

/** One curl per (target, interface): connect + TLS timings; the HTTP code does not matter (fake-TLS, REALITY). */
export function ruProbeScript(targets: ProbeTarget[], ifaces: string[]): string {
    const lines = targets.map((t) => `${t.ip} ${t.port} ${t.sni}`).join('\n');
    return [
        `IFACES=${JSON.stringify(ifaces.join(' '))}`,
        `while read -r ip port sni; do`,
        `  [ -n "$ip" ] || continue`,
        `  for w in \${IFACES:-direct}; do`,
        `    if [ "$w" = direct ]; then bind=""; else bind="--interface $w"; fi`,
        `    o=$(curl -sk -o /dev/null $bind -m 12 --connect-timeout 6 --resolve "$sni:$port:$ip" -w "%{http_code} %{time_connect} %{time_appconnect}" "https://$sni:$port/" 2>/dev/null); rc=$?`,
        `    echo "P|$ip:$port/$sni|$w|$rc|$o"`,
        `  done`,
        `done <<'T'`,
        lines,
        'T',
    ].join('\n');
}

export interface ProbeRow {
    target: string;
    via: string;
    rc: number;
    tcp: boolean;
    tls: boolean;
    ms?: number;
}

export function parseProbe(out: string): ProbeRow[] {
    return out
        .split('\n')
        .filter((l) => l.startsWith('P|'))
        .map((l) => {
            const [, target, via, rc, rest = ''] = l.split('|');
            const [, connect = '0', tls = '0'] = rest.trim().split(/\s+/);
            const c = Number(connect);
            const t = Number(tls);
            return { target, via, rc: Number(rc), tcp: c > 0, tls: t > 0, ...(t > 0 ? { ms: Math.round(t * 1000) } : {}) };
        });
}

export type Verdict = 'ok' | 'blocked-ru' | 'partial' | 'down' | 'unknown';

/** Per target: home ISPs vs the datacenter control. */
export function ruVerdict(home: ProbeRow[], control: ProbeRow[], isp: Record<string, string> = {}): Record<string, { verdict: Verdict; note: string }> {
    const out: Record<string, { verdict: Verdict; note: string }> = {};
    for (const target of [...new Set(home.map((r) => r.target))]) {
        const rows = home.filter((r) => r.target === target);
        const ok = rows.filter((r) => r.tls);
        const bad = rows.filter((r) => !r.tls);
        const dc = control.filter((r) => r.target === target);
        const dcOk = dc.some((r) => r.tls);
        const name = (r: ProbeRow) => isp[r.via] ?? r.via;
        const how = (r: ProbeRow) => (r.tcp ? 'TCP есть, TLS нет' : r.rc === 28 ? 'таймаут' : `нет TCP (curl ${r.rc})`);
        if (!rows.length) out[target] = { verdict: 'unknown', note: 'нет результатов' };
        else if (!bad.length) out[target] = { verdict: 'ok', note: ok.map((r) => `${name(r)} ${r.ms} мс`).join(', ') };
        else if (ok.length) out[target] = { verdict: 'partial', note: `не проходит у ${bad.map((r) => `${name(r)} (${how(r)})`).join(', ')}; проходит у ${ok.map(name).join(', ')}` };
        else if (!dc.length) out[target] = { verdict: 'unknown', note: `не проходит ни у одного провайдера (${bad.map(how).join('; ')}); контроль из ДЦ не запускали` };
        else if (dcOk)
            out[target] = {
                verdict: 'blocked-ru',
                note: `не проходит ни у одного домашнего провайдера (${bad.map((r) => `${name(r)}: ${how(r)}`).join('; ')}), а из ДЦ проходит — ТСПУ режет адрес:порт. Сначала откат DNS, потом разбор`,
            };
        else out[target] = { verdict: 'down', note: 'не отвечает ни из дома, ни из ДЦ — сервер или порт не работают' };
    }
    return out;
}

/** "wan0=ISP-A,wan1=ISP-B" → interfaces and their ISP labels. */
export function parseIfaces(raw: string): { ifaces: string[]; isp: Record<string, string> } {
    const pairs = raw.split(',').map((s) => s.trim()).filter(Boolean).map((s) => s.split('=').map((x) => x.trim()));
    return { ifaces: pairs.map(([i]) => i), isp: Object.fromEntries(pairs.filter((x) => x[1]).map(([i, n]) => [i, n])) };
}

/** Vantage host, its ISP interfaces and the datacenter control come from the environment. */
const probeEnv = parseIfaces(process.env.MIA_PROBE_IFACES ?? 'wan0=ISP-A,wan1=ISP-B');
export const RU_PROBE_DEFAULTS = { from: process.env.MIA_PROBE_FROM ?? 'probe-ru', ifaces: probeEnv.ifaces, isp: probeEnv.isp, control: process.env.MIA_PROBE_CONTROL ?? '' };

export async function ruProbe(
    ctx: Ctx,
    o: { to: string[]; sni?: string; from?: string; ifaces?: string[]; control?: string },
): Promise<{ results: Record<string, { verdict: Verdict; note: string }>; blocked: string[]; rows: ProbeRow[]; control: ProbeRow[] }> {
    const targets = o.to.map((t) => parseTarget(t, o.sni));
    const inv = ctx.inventory();
    const from = o.from ?? RU_PROBE_DEFAULTS.from;
    const ifaces = o.ifaces ?? RU_PROBE_DEFAULTS.ifaces;
    const homeRes = await ctx.transport.exec(inv.get(from), ruProbeScript(targets, ifaces), { timeoutMs: 30_000 + targets.length * ifaces.length * 13_000, noSudo: true });
    if (!homeRes.ok && !homeRes.stdout.includes('P|')) throw new Error(`${from}: ${homeRes.error ?? homeRes.stderr}`);
    const rows = parseProbe(homeRes.stdout);
    let control: ProbeRow[] = [];
    const ctl = o.control ?? RU_PROBE_DEFAULTS.control;
    if (ctl) {
        const c = await ctx.transport.exec(inv.get(ctl), ruProbeScript(targets, []), { timeoutMs: 30_000 + targets.length * 13_000, noSudo: true });
        control = parseProbe(c.stdout).map((r) => ({ ...r, via: ctl }));
    }
    const results = ruVerdict(rows, control, RU_PROBE_DEFAULTS.isp);
    return { results, blocked: Object.entries(results).filter(([, v]) => v.verdict === 'blocked-ru').map(([k]) => k), rows, control };
}

export function registerRuProbeTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'ru_probe',
        'Is an address reachable from Russia (or any censored network): a TLS handshake from a vantage host through EVERY local ISP interface (MIA_PROBE_FROM, MIA_PROBE_IFACES) with the address forced (--resolve, not DNS), plus a control from a datacenter host (MIA_PROBE_CONTROL). Verdict per target: ok | partial (one ISP) | blocked-ru (both ISPs fail, datacenter passes = DPI (TSPU) blocks address:port — roll the DNS back first) | down. Read-only, one handshake per pair; the gate before and after any address switch (ingress, new node).',
        {
            to: z.array(z.string().regex(/^[\w.-]+(:\d{1,5})?(\/[\w.-]+)?$/)).min(1).max(40).describe('targets: "ip:port" or "ip:port/sni" (default port 443)'),
            sni: z.string().regex(/^[\w.-]+$/).optional().describe('SNI for targets without their own'),
            from: z.string().optional().describe('host with the home ISPs (default MIA_PROBE_FROM; only read, nothing changes there)'),
            ifaces: z.array(z.string().regex(/^[\w.-]+$/)).optional().describe('interfaces = ISPs (default from MIA_PROBE_IFACES)'),
            control: z.string().optional().describe('datacenter host for the control probe (default MIA_PROBE_CONTROL; "" = none)'),
        },
        (args) => run(async () => ruProbe(ctx, args)),
    );
}
