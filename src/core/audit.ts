import { Host, Policy } from './inventory.js';
import { PanelNode, nodeState } from './panel.js';
import { HostFacts, UfwRule, isWildcardOrPublic } from './probe.js';

export type Severity = 'crit' | 'warn' | 'info';

export interface Finding {
    sev: Severity;
    code: string;
    msg: string;
}

const SEV_ORDER: Record<Severity, number> = { crit: 0, warn: 1, info: 2 };

/** Role services whose state the edge/remnanode checks already report with a precise code. */
const ROLE_CHECKED = new Set(['remnanode', 'docker', 'tailscaled', 'fail2ban', 'node_exporter', 'beszel-agent', 'ufw', 'ipset-load', 'certbot', 'geo-updater']);

/**
 * Checks a host against the fleet's current baseline (edge / remnanode roles) — what the nodes
 * actually run as of 2026-09-27: vps-edge-run.sh bootstrap + ufw-blacklist.sh ipsets, MGMT-PORTS,
 * beszel-agent, automatic updates off —
 * general health for every host, the inventory's services, and the panel's view of the node.
 * Codes are stable: policy.skip takes a code or a prefix ("tune" skips tune.*).
 */
export function audit(host: Host, f: HostFacts, panelNode?: PanelNode | null): Finding[] {
    const out: Finding[] = [];
    const add = (sev: Severity, code: string, msg: string) => out.push({ sev, code, msg });
    const p = host.policy as Required<Policy>;

    if (!f.reachable) {
        add('crit', 'reach', `недоступен: ${f.error ?? 'нет ответа'}`);
        if (panelNode) panelChecks(host, panelNode, add);
        return filter(out, p.skip);
    }
    if (f.error) add('warn', 'probe.partial', f.error);

    // ---------------------------------------------------------------- health, every host
    for (const d of f.disks) {
        if (d.usedPct >= p.diskCritPct) add('crit', 'disk.full', `${d.mount} занято ${d.usedPct}% из ${d.sizeGiB} ГиБ`);
        else if (d.usedPct >= p.diskWarnPct) add('warn', 'disk.full', `${d.mount} занято ${d.usedPct}% из ${d.sizeGiB} ГиБ`);
    }
    if (f.mem && f.mem.usedPct >= p.memWarnPct) add('warn', 'mem.high', `память занята на ${f.mem.usedPct}% (свободно ${f.mem.availMiB} МиБ)`);
    const hot = Object.entries(f.temps).filter(([, c]) => c >= p.tempWarnC);
    if (hot.length) add('warn', 'temp.high', `горячо: ${hot.map(([k, c]) => `${k} ${c}°C`).join(', ')}`);
    if (f.load && f.cpus && f.load[1] / f.cpus > 2) add('warn', 'load.high', `нагрузка ${f.load[1]} на ${f.cpus} ядер`);
    if (f.rebootRequired) add('warn', 'reboot.required', `нужна перезагрузка${f.rebootPkgs.length ? ` (${f.rebootPkgs.slice(0, 5).join(', ')})` : ''}`);
    if (f.apt) {
        const sec = f.apt.upgradable.filter((u) => u.security).length;
        if (sec) add('warn', 'apt.security', `ждут security-обновления: ${sec}`);
        else if (f.apt.upgradable.length) add('info', 'apt.updates', `ждут обновления: ${f.apt.upgradable.length}`);
    }
    // session-*.scope and other transient scopes are not services
    const failed = f.failedUnits.filter((u) => !u.endsWith('.scope'));
    if (failed.length) add('warn', 'units.failed', `упавшие юниты: ${failed.join(', ')}`);
    if (f.time?.ntpSynced === false) add('warn', 'time.unsynced', 'часы не синхронизированы по NTP (REALITY/TLS ломаются при расхождении)');

    // updates (fleet policy 2026-09-28): security patches automatically, reboots only by hand
    if (f.unattended) {
        const periodic = f.aptAuto['APT::Periodic::Unattended-Upgrade'];
        const timer = f.units['apt-daily-upgrade.timer'];
        const off: string[] = [];
        if (!f.unattended.installed) off.push('unattended-upgrades not installed');
        if (!periodic || periodic === '0') off.push('APT::Periodic::Unattended-Upgrade off');
        if (timer && timer.enabled !== 'enabled' && timer.enabled !== 'static') off.push(`apt-daily-upgrade.timer ${timer.enabled}`);
        if (p.securityUpdates && off.length) add('warn', 'updates.security_off', `security-обновления не ставятся сами: ${off.join(', ')} (updates_policy)`);
        if (!p.securityUpdates && !off.length) add('info', 'updates.security_on', 'автообновления включены, хотя policy.securityUpdates: false');
        if (!p.autoReboot && f.aptAuto['Unattended-Upgrade::Automatic-Reboot'] === 'true') add('warn', 'updates.auto_reboot', 'unattended-upgrades перезагружает сервер сам (по правилам флота — только руками)');
        const wide = f.unattended.origins.filter((o) => /-(updates|proposed|backports)\b|\ba=[\w-]*-(updates|proposed|backports)/.test(o));
        if (wide.length) add('info', 'updates.not_security_only', `автообновления ставят не только security: ${wide.join(', ')}`);
    }

    const unit = (u: string) => f.units[u];
    const active = (u: string) => unit(u)?.active === 'active';

    // ---------------------------------------------------------------- edge baseline
    if (host.roles.includes('edge')) {
        if (!f.ufw) add('crit', 'fw.missing', 'ufw не установлен');
        else {
            if (!f.ufw.active) {
                add('crit', 'fw.inactive', 'ufw выключен: все слушающие порты открыты наружу (если их не прикрывает MGMT-PORTS/iptables)');
                const exposed = f.listen.filter((s) => isWildcardOrPublic(s.addr) && p.mgmtPorts.includes(s.port));
                if (exposed.length && f.mgmt.rules === undefined) add('crit', 'fw.exposed', `служебные порты открыты наружу: ${exposed.map((s) => `${s.port}/${s.proto}${s.process ? `(${s.process})` : ''}`).join(', ')}`);
            }
            if (f.ufw.defaultIn && !/deny|reject/.test(f.ufw.defaultIn)) add('crit', 'fw.default_in', `входящие по умолчанию: ${f.ufw.defaultIn}`);
            const pub = publicAllows(f.ufw.rules);
            const extra = new Set<string>();
            const guardSet = new Set<number>([
                ...(f.mgmt.rules && f.mgmt.jumps ? (f.mgmt.list ?? []).map((x) => Number(x.split('/')[0])) : []),
                ...f.guardPorts.filter((x) => /^\d+$/.test(x)).map(Number),
            ]);
            // a management port is exposed only if something listens on it publicly and no guard chain covers it
            const exposedMgmt = (ports: number[]) =>
                [...new Set(f.listen.filter((l) => ports.includes(l.port) && isWildcardOrPublic(l.addr) && !guardSet.has(l.port)).map((l) => `${l.port}/${l.proto}${l.process ? `(${l.process})` : ''}`))];
            for (const r of pub) {
                const specs = expandPort(r.port);
                const bad = specs.filter((s) => !p.publicPorts.includes(s));
                if (!bad.length) continue;
                const mgmt = bad.some((s) => s === 'any' || portHits(s, p.mgmtPorts));
                // MGMT-PORTS / ADMIN-PORTS sit in front of ufw and let only the tailnet and home in: a ufw allow of a
                // port they guard is not exposure. "ALLOW Anywhere on <public iface>" (ingresses: every public port by
                // design) is exposure only for management ports that actually listen publicly and are not guarded.
                const hit = p.mgmtPorts.filter((x) => bad.some((s) => s === 'any' || portHits(s, [x])));
                const exposed = exposedMgmt(hit);
                const allGuarded = hit.every((x) => guardSet.has(x));
                if (mgmt && exposed.length) add('crit', 'fw.public_mgmt', `служебный порт открыт наружу: ${exposed.join(', ')} (ALLOW ${r.to}${r.v6 ? ' (v6)' : ''} from ${r.from})`);
                else if (mgmt && allGuarded) add('info', 'fw.mgmt_guarded', `ufw пускает ${r.to}${r.v6 ? ' (v6)' : ''} отовсюду, но служебные порты прикрыты MGMT-PORTS/ADMIN-PORTS (только tailnet и дом)`);
                else if (mgmt) add('info', 'fw.mgmt_idle', `ufw пускает ${r.to}${r.v6 ? ' (v6)' : ''} отовсюду; служебные порты наружу не слушают`);
                else for (const b of bad) extra.add(b);
            }
            // inbound ports differ per node (443, 1443-4444, 5443/5444, 9443/9444 …): listed, not alarmed
            if (extra.size) add('info', 'fw.public_port', `открыты наружу сверх policy.publicPorts: ${[...extra].join(', ')}`);
            if (!f.ufw.rules.some((r) => r.iface === 'tailscale0' && /ALLOW IN/.test(r.action))) add('warn', 'fw.tailscale', 'в ufw нет ALLOW IN на tailscale0: SSH/API через Tailscale может резаться');
        }

        if (!active('tailscaled')) add('crit', 'ts.down', `tailscaled: ${unit('tailscaled')?.active ?? 'не установлен'}`);
        else if (f.tailscale && f.tailscale.backendState !== 'Running') add('crit', 'ts.down', `tailscale в состоянии ${f.tailscale.backendState}`);

        if (f.sshd.passwordauthentication && f.sshd.passwordauthentication !== 'no') add('crit', 'ssh.password', 'sshd пускает по паролю (PasswordAuthentication)');
        if (f.sshd.permitrootlogin && f.sshd.permitrootlogin !== 'no') add('warn', 'ssh.root_login', `sshd PermitRootLogin ${f.sshd.permitrootlogin}`);

        if (!active('fail2ban')) add('warn', 'f2b.inactive', `fail2ban: ${unit('fail2ban')?.active ?? 'не установлен'}`);
        else if (f.fail2ban) {
            const have = new Set(f.fail2ban.map((j) => j.jail));
            const miss = p.jails.filter((j) => !have.has(j));
            if (miss.length) add('warn', 'f2b.jail_missing', `нет jail'ов fail2ban: ${miss.join(', ')}`);
        }
        if (!active('node_exporter')) add('warn', 'exporter.inactive', `node_exporter: ${unit('node_exporter')?.active ?? 'не установлен'}`);
        if (!active('beszel-agent')) add('warn', 'beszel.inactive', `beszel-agent: ${unit('beszel-agent')?.active ?? 'не установлен'}`);

        // MGMT-PORTS: management ports only from the tailnet + home WANs (fleet-wide since 2026-09-26)
        if (f.mgmt.rules === undefined) add('warn', 'mgmt.missing', 'нет цепочки iptables MGMT-PORTS (lock-mgmt-ports-apply.sh)');
        else if (!f.mgmt.jumps) add('warn', 'mgmt.unhooked', 'цепочка MGMT-PORTS есть, но INPUT в неё не переходит');

        // ipset blacklists (ufw-blacklist.sh replaced the rugov nftables updater in August 2026)
        if (!f.blacklist.cron) add('warn', 'blacklist.cron', 'нет /etc/cron.d/ufw-blacklist: блок-листы не обновляются');
        const sets = Object.entries(f.ipsets);
        if (!sets.length) add('warn', 'blacklist.missing', 'ipset\'ы не загружены (ufw-blacklist.sh / ipset-load)');
        else {
            const empty = sets.filter(([n, c]) => /black|white/i.test(n) && c === 0).map(([n]) => n);
            if (empty.length) add('warn', 'blacklist.empty', `пустые ipset'ы: ${empty.join(', ')}`);
        }
        if (unit('ipset-load') && unit('ipset-load').enabled !== 'enabled') add('warn', 'blacklist.boot', 'ipset-load.service не включён: после перезагрузки списки пропадут');
        if (f.legacyRugov) add('info', 'blacklist.legacy', 'осталась старая цепочка rugov в nftables (её заменил ufw-blacklist.sh)');


        const cc = f.sysctl['net.ipv4.tcp_congestion_control'];
        if (cc && cc !== 'bbr') add('warn', 'tune.bbr', `tcp_congestion_control=${cc} (тюнинг не применён?)`);
        const qd = f.sysctl['net.core.default_qdisc'];
        if (qd && qd !== 'fq') add('info', 'tune.qdisc', `default_qdisc=${qd}`);
        if (f.sysctl['net.ipv4.ip_forward'] === '0') add('warn', 'tune.forward', 'ip_forward=0 (exit node и форвардинг выключены)');
        const cmax = Number(f.sysctl['net.netfilter.nf_conntrack_max']);
        const ccount = Number(f.sysctl['net.netfilter.nf_conntrack_count']);
        if (cmax && ccount && (ccount / cmax) * 100 >= p.conntrackWarnPct)
            add('warn', 'conntrack.high', `conntrack ${ccount}/${cmax} (${Math.round((ccount / cmax) * 100)}%)`);
    }

    // ---------------------------------------------------------------- remnanode
    if (host.roles.includes('remnanode')) {
        if (!active('docker')) add('crit', 'docker.inactive', `docker: ${unit('docker')?.active ?? 'не установлен'}`);
        const rn = f.remnanode;
        if (!rn) add('crit', 'node.compose', 'нет /opt/remnanode/docker-compose.yml');
        else {
            if (rn.secret_key !== 'present') add('crit', 'node.secret', 'в compose remnanode нет SECRET_KEY');
            if (rn.geo_volumes === '0') add('warn', 'node.volumes', 'geo-файлы roscomvpn не смонтированы в remnanode');
            if (rn.cert_volume === '0') add('warn', 'node.volumes', '/opt/certbot/certs не смонтирован в remnanode');
            const port = Number(rn.node_port) || 2222;
            if (!f.listen.some((s) => s.port === port && s.proto === 'tcp')) add('warn', 'node.port', `на NODE_PORT ${port} никто не слушает`);
        }
        const c = f.docker?.containers.find((x) => x.name === 'remnanode');
        if (!c) add('crit', 'node.container', 'нет контейнера remnanode');
        else {
            if (c.state !== 'running') add('crit', 'node.container', `remnanode ${c.state}: ${c.status}`);
            if ((c.restarts ?? 0) > 3) add('warn', 'node.restarts', `remnanode перезапускался ${c.restarts} раз`);
            const img = f.docker?.images.find((i) => i.ref === c.image);
            if (img && c.imageId && img.id && img.id !== c.imageId) add('info', 'node.pending_recreate', 'новый образ remnanode скачан, но контейнер работает на старом');
        }

        const cert = pickCert(host, f);
        if (!cert) add('info', 'cert.missing', 'нет сертификата в /opt/certbot/certs/live (для нод только с REALITY это нормально)');
        else if (cert.daysLeft !== undefined) {
            if (cert.daysLeft <= p.certCritDays) add('crit', 'cert.expiring', `сертификат истекает через ${cert.daysLeft} дн.`);
            else if (cert.daysLeft <= p.certWarnDays) add('warn', 'cert.expiring', `сертификат истекает через ${cert.daysLeft} дн.`);
            if (host.domain && cert.sans.length && !cert.sans.includes(host.domain)) add('warn', 'cert.domain', `сертификат на ${cert.sans.join(', ')}, а домен хоста ${host.domain}`);
        }

        if (!active('update-roscomvpn-geo.timer')) add('warn', 'geo.timer', `таймер обновления geo: ${unit('update-roscomvpn-geo.timer')?.active ?? 'не установлен'}`);
        if (f.geoService?.Result && f.geoService.Result !== 'success') add('warn', 'geo.failed', `последнее обновление geo: ${f.geoService.Result}`);
        if (!f.geoFiles.length) add('warn', 'geo.missing', 'нет /opt/remnanode/roscomvpn-*.dat');
        else if (f.now && f.geoState?.lastRun) {
            // v2 rewrites a file only when upstream changed it and only files xray uses: freshness is the last good run
            if (f.geoState.failed) add('warn', 'geo.failed', 'последний прогон обновления geo завершился ошибкой (roscomvpn_geo_last_run_failed)');
            const ageH = Math.round((f.now - f.geoState.lastRun) / 3600);
            if (ageH > p.geoMaxAgeHours) add('warn', 'geo.stale', `обновление geo не запускалось ${ageH} ч`);
        } else if (f.now) {
            // the updater rewrites a file only when upstream changed it: a recent successful run means the data is current
            const lastOk = [f.geoService, f.geoService2].filter((g) => g?.Result === 'success').map((g) => parseSystemdTime(g!.ExecMainExitTimestamp)).filter((t): t is number => t !== undefined);
            const oldest = Math.min(...f.geoFiles.map((g) => g.mtime));
            const fresh = Math.max(oldest, ...lastOk);
            const ageH = Math.round((f.now - fresh) / 3600);
            if (ageH > p.geoMaxAgeHours) add('warn', 'geo.stale', lastOk.length ? `geo не обновлялись ${ageH} ч` : `geo-файлам ${ageH} ч, успешных запусков обновления не видно`);
        }

    }

    // ---------------------------------------------------------------- inventory services
    for (const svc of host.services) {
        const st = f.services.find((s) => s.name === svc.name);
        if (!st) continue;
        const expect = svc.expect ?? 'running';
        // the role checks above already cover these with better messages
        if (host.roles.includes('edge') && ROLE_CHECKED.has(svc.name)) continue;
        if (st.compose === 'missing-file') add(expect === 'running' ? 'crit' : 'warn', 'svc.missing', `${svc.name}: нет ${svc.compose}`);
        else if (st.compose && expect === 'running') {
            const parts = st.compose === 'none' ? [] : st.compose.split(/\s+/).filter(Boolean);
            const down = parts.filter((x) => !x.endsWith(':running'));
            if (!parts.length) add('crit', 'svc.down', `${svc.name}: compose-проект не поднят`);
            else if (down.length) add('crit', 'svc.down', `${svc.name}: ${down.join(', ')}`);
        }
        if (st.container && svc.container && !svc.compose && expect === 'running' && st.container !== 'running')
            add('crit', 'svc.down', `${svc.name}: контейнер ${st.container}`);
        if (st.unit) {
            if (st.unit === 'absent') add(expect === 'running' ? 'crit' : 'warn', 'svc.missing', `${svc.name}: юнит ${svc.unit} не установлен`);
            else if (expect === 'running' && !st.unit.startsWith('active/') && !(svc.unit?.startsWith('wg-quick@') && f.ifaces.includes(svc.unit.slice('wg-quick@'.length))))
                add('crit', 'svc.down', `${svc.name}: ${svc.unit} ${st.unit.split('/')[0]}`);
        }
    }

    if (panelNode !== undefined) {
        if (panelNode) panelChecks(host, panelNode, add);
        else if (host.roles.includes('remnanode')) add('info', 'panel.missing', 'в панели нет ноды для этого хоста (задайте panelNode в fleet.yaml)');
    }

    return filter(out, p.skip);
}

function panelChecks(host: Host, n: PanelNode, add: (sev: Severity, code: string, msg: string) => void) {
    const st = nodeState(n);
    if (st === 'DISCONNECTED') add('crit', 'panel.disconnected', `нода «${n.name}» в панели ОТКЛЮЧЕНА${n.lastStatusMessage ? `: ${n.lastStatusMessage}` : ''}`);
    else if (st === 'disabled') add('info', 'panel.disabled', `нода «${n.name}» в панели выключена`);
}

function filter(list: Finding[], skip: string[]): Finding[] {
    return list
        .filter((x) => !skip.some((s) => x.code === s || x.code.startsWith(s + '.')))
        .sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
}

/** Certificate of the host: the one covering its domain, else "remnanode", else the first. */
export function pickCert(host: Host, f: HostFacts) {
    return (host.domain && f.certs.find((c) => c.sans.includes(host.domain!))) || f.certs.find((c) => c.name === 'remnanode') || f.certs[0];
}

/** Does a port spec ("22/tcp", "2222", "9000:9200/tcp") cover one of the ports? */
function portHits(spec: string, ports: number[]): boolean {
    const p = spec.split('/')[0];
    if (p.includes(':')) {
        const [a, b] = p.split(':').map(Number);
        return ports.some((x) => x >= a && x <= b);
    }
    return ports.includes(Number(p));
}

/** "Mon 2026-09-28 03:00:01 UTC" (systemctl show) → unix seconds; undefined when empty or unparsable. */
export function parseSystemdTime(v?: string): number | undefined {
    const m = v?.match(/(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?: (\S+))?/);
    if (!m) return undefined;
    const tz = m[3] && /^(UTC|GMT)$/.test(m[3]) ? 'Z' : m[3] && /^[+-]\d{2}$/.test(m[3]) ? `${m[3]}:00` : m[3] === 'MSK' ? '+03:00' : 'Z';
    const t = Date.parse(`${m[1]}T${m[2]}${tz}`);
    return Number.isFinite(t) ? Math.floor(t / 1000) : undefined;
}

/** UFW rules that let the internet in: ALLOW/LIMIT IN from Anywhere, not bound to tailscale0. */
/** Interfaces that never face the internet: tailnet, docker bridges, veth, WireGuard/AmneziaWG, libvirt/CNI. */
export const INTERNAL_IFACE = /^(lo|tailscale\d*|docker\d*|br-[\w-]+|veth\w*|wg[\w-]*|awg[\w-]*|amn\d*|virbr\d*|cni\w*|flannel[\w.]*)$/;

export function publicAllows(rules: UfwRule[]): UfwRule[] {
    return rules.filter((r) => /^(ALLOW|LIMIT)( IN)?$/.test(r.action) && !(r.iface && INTERNAL_IFACE.test(r.iface)) && /^Anywhere$/.test(r.from));
}

/** "443" → 443/tcp + 443/udp; "80/tcp" stays; "Anywhere" → any. */
export function expandPort(spec: string): string[] {
    if (spec === 'Anywhere') return ['any'];
    if (/\/(tcp|udp)$/.test(spec)) return [spec];
    return [`${spec}/tcp`, `${spec}/udp`];
}

export function worst(findings: Finding[]): Severity | 'ok' {
    return findings.length ? findings[0].sev : 'ok';
}

// ---------------------------------------------------------------- compact status row

const dur = (s?: number) => (s === undefined ? undefined : s >= 86400 ? `${Math.floor(s / 86400)}d` : s >= 3600 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 60)}m`);

export function statusRow(host: Host, f: HostFacts, findings: Finding[], panelNode?: PanelNode | null): Record<string, unknown> {
    if (!f.reachable) {
        return {
            host: host.name,
            title: host.title,
            state: 'UNREACHABLE',
            error: f.error,
            panel: panelNode ? `${nodeState(panelNode)}${panelNode.usersOnline ? ` ${panelNode.usersOnline}u` : ''}` : undefined,
        };
    }
    const root = f.disks.find((d) => d.mount === '/') ?? f.disks[0];
    const node = f.docker?.containers.find((c) => c.name === 'remnanode');
    const cert = pickCert(host, f);
    const sec = f.apt?.upgradable.filter((u) => u.security).length ?? 0;
    return {
        host: host.name,
        title: host.title,
        state: worst(findings),
        up: dur(f.uptimeS),
        load: f.load?.[1],
        cpu: f.cpus,
        mem: f.mem ? `${f.mem.usedPct}%` : undefined,
        temp: Object.keys(f.temps).length ? `${Math.max(...Object.values(f.temps))}°` : undefined,
        disk: root ? `${root.usedPct}%` : undefined,
        updates: f.apt ? `${f.apt.upgradable.length}${sec ? `/${sec}sec` : ''}` : undefined,
        reboot: f.rebootRequired || undefined,
        node: host.roles.includes('remnanode') ? (node ? node.state : 'absent') : undefined,
        cert: host.roles.includes('remnanode') ? (cert ? `${cert.daysLeft}d` : '-') : undefined,
        ts: f.tailscale?.backendState,
        panel: panelNode ? `${nodeState(panelNode)}${panelNode.usersOnline !== undefined ? ` ${panelNode.usersOnline}u` : ''}` : undefined,
        issues: findings.filter((x) => x.sev !== 'info').map((x) => x.code).join(' ') || undefined,
    };
}
