/**
 * «Дальше»: what to do about a result, one key each. From a status or an audit — the fixes for the
 * codes it found, on exactly the hosts that have them; after a run — the failed or the skipped hosts,
 * and a reboot where the update asked for one.
 */
export interface Next {
    label: string;
    hint?: string;
    tool?: string;
    preset?: Record<string, unknown>;
    /** a setup flow instead of a tool */
    setup?: 'host-tailnet';
}

const FIX: Array<{ code: RegExp; tool: string; label: string; preset?: Record<string, unknown> }> = [
    { code: /^apt\.(security|updates)$/, tool: 'apt_upgrade', label: 'обновить пакеты' },
    { code: /^reboot\.required$/, tool: 'host_reboot', label: 'перезагрузить, где нужен ребут' },
    { code: /^node\.pending_recreate$/, tool: 'remnanode_update', label: 'обновить remnanode' },
    { code: /^updates\.security_off$/, tool: 'updates_policy', label: 'включить автообновления security' },
    { code: /^geo\.(stale|failed|missing)$/, tool: 'geo_update', label: 'обновить geo-файлы' },
    { code: /^blacklist\.(cron|missing|empty|boot)$/, tool: 'blacklist_update', label: 'обновить блок-листы' },
    { code: /^cert\.expiring$/, tool: 'cert_renew', label: 'продлить сертификаты' },
    { code: /^disk\.full$/, tool: 'disk_cleanup', label: 'почистить диск' },
    { code: /^tune\.(bbr|qdisc)$/, tool: 'tuning_apply', label: 'применить тюнинг сети' },
    { code: /^f2b\.inactive$/, tool: 'service_action', label: 'перезапустить fail2ban', preset: { service: 'fail2ban', action: 'restart' } },
    { code: /^beszel\.inactive$/, tool: 'service_action', label: 'перезапустить beszel-agent', preset: { service: 'beszel-agent', action: 'restart' } },
];

const plural = (n: number) => (n % 10 === 1 && n % 100 !== 11 ? 'сервер' : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 'сервера' : 'серверов');
const few = (hosts: string[]) => `${hosts.slice(0, 6).join(' ')}${hosts.length > 6 ? ` … ещё ${hosts.length - 6}` : ''}`;

type Row = Record<string, unknown>;

/** code → hosts, from a status (rows with issue codes) or an audit (byCode). */
function codeHosts(tool: string, data: Row): Map<string, Set<string>> {
    const out = new Map<string, Set<string>>();
    const add = (code: string, host: string) => {
        if (!out.has(code)) out.set(code, new Set());
        out.get(code)!.add(host);
    };
    if (tool === 'fleet_status') {
        for (const r of (data.rows as Row[] | undefined) ?? []) {
            if (r.state === 'UNREACHABLE' || r.state === 'not in fleet.yaml' || r.state === 'offline') continue;
            const host = String(r.host);
            for (const code of String(r.issues ?? '').split(/\s+/).filter(Boolean)) add(code, host);
            if (Number(String(r.updates ?? '').split('/')[0]) > 0) add('apt.updates', host);
            if (r.reboot) add('reboot.required', host);
        }
    }
    if (tool === 'fleet_audit') for (const [code, hosts] of Object.entries((data.byCode as Record<string, string> | undefined) ?? {})) for (const h of hosts.split(/,\s*/).filter(Boolean)) add(code, h);
    return out;
}

export function nextActions(tool: string, args: Record<string, unknown>, data: unknown, has: (tool: string) => boolean): Next[] {
    const d = (data ?? {}) as Row;
    const out: Next[] = [];
    if (tool === 'fleet_status' || tool === 'fleet_audit') {
        const found = codeHosts(tool, d);
        for (const f of FIX) {
            const hosts = [...new Set([...found].filter(([code]) => f.code.test(code)).flatMap(([, h]) => [...h]))];
            if (!hosts.length || !has(f.tool)) continue;
            // two fixes on the same tool (fail2ban / beszel) stay apart: their presets differ
            out.push({ label: `${f.label}: ${hosts.length} ${plural(hosts.length)}`, hint: few(hosts), tool: f.tool, preset: { ...(f.preset ?? {}), target: hosts.join(',') } });
        }
        if (tool === 'fleet_status') {
            const rows = (d.rows as Row[] | undefined) ?? [];
            const crit = rows.filter((r) => r.state === 'crit').map((r) => String(r.host));
            if (crit.length) out.push({ label: `разобрать критичное: аудит ${crit.length} ${plural(crit.length)}`, hint: few(crit), tool: 'fleet_audit', preset: { target: crit.join(',') } });
            const dead = rows.filter((r) => r.state === 'UNREACHABLE').map((r) => String(r.host));
            if (dead.length === 1) out.push({ label: `что с ${dead[0]}: устройство в tailnet`, tool: 'tailnet_devices', preset: { filter: dead[0] } });
            const extra = rows.filter((r) => r.state === 'not in fleet.yaml' || r.state === 'offline').length;
            if (extra) out.push({ label: `добавить в fleet.yaml устройства tailnet: ${extra}`, setup: 'host-tailnet' });
        }
    }
    // after a run: what failed, what did not start, what now wants a reboot
    const results = (d.results as Row[] | undefined) ?? [];
    const failed = results.filter((r) => r.ok === false && r.host).map((r) => String(r.host));
    if (failed.length && 'target' in args) out.push({ label: `повторить на упавших: ${failed.length}`, hint: few(failed), tool, preset: { ...args, target: failed.join(',') } });
    const notRun = ((d.notRun as string[] | undefined) ?? []).filter(Boolean);
    if (notRun.length && 'target' in args) out.push({ label: `продолжить на оставшихся: ${notRun.length}`, hint: few(notRun), tool, preset: { ...args, target: notRun.join(',') } });
    const reboot = results.filter((r) => r.ok && /REBOOT_REQUIRED/.test(String(r.output ?? ''))).map((r) => String(r.host));
    if (reboot.length && tool !== 'host_reboot' && has('host_reboot')) out.push({ label: `перезагрузить, где теперь нужен ребут: ${reboot.length}`, hint: few(reboot), tool: 'host_reboot', preset: { target: reboot.join(',') } });
    return out.filter((n) => !n.tool || has(n.tool)).slice(0, 8);
}
