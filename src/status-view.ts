import { c, clipVisible, strip } from './color.js';

/** Short Russian meaning of every audit code, for the legend under the status table. */
export const CODE_RU: Record<string, string> = {
    reach: 'сервер недоступен',
    'probe.partial': 'сбор данных неполный',
    'disk.full': 'диск заполнен',
    'mem.high': 'мало памяти',
    'temp.high': 'высокая температура',
    'load.high': 'высокая нагрузка',
    'reboot.required': 'нужна перезагрузка',
    'apt.security': 'ждут security-обновления',
    'apt.updates': 'ждут обновления',
    'units.failed': 'есть упавшие systemd-юниты',
    'time.unsynced': 'часы не синхронизированы',
    'updates.security_off': 'security-обновления не ставятся сами',
    'updates.security_on': 'автообновления включены вопреки политике',
    'updates.auto_reboot': 'сервер перезагружается сам',
    'updates.not_security_only': 'автообновления не только security',
    'fw.missing': 'нет ufw',
    'fw.inactive': 'ufw выключен',
    'fw.exposed': 'служебные порты открыты наружу',
    'fw.default_in': 'входящие разрешены по умолчанию',
    'fw.public_mgmt': 'служебный порт открыт в ufw',
    'fw.mgmt_guarded': 'ufw открыт, но порт прикрыт MGMT-PORTS',
    'fw.public_port': 'открыты порты сверх политики (для нод — инбаунды)',
    'fw.tailscale': 'ufw не пускает tailscale0',
    'ts.down': 'Tailscale не работает',
    'ssh.password': 'ssh пускает по паролю',
    'ssh.root_login': 'ssh пускает root',
    'f2b.inactive': 'fail2ban не работает',
    'f2b.jail_missing': 'не хватает jail’ов fail2ban',
    'exporter.inactive': 'node_exporter не работает',
    'beszel.inactive': 'beszel-agent не работает',
    'mgmt.missing': 'нет цепочки MGMT-PORTS',
    'mgmt.unhooked': 'MGMT-PORTS не подключена к INPUT',
    'blacklist.cron': 'блок-листы не обновляются (нет крона)',
    'blacklist.missing': 'нет ipset-блок-листов',
    'blacklist.empty': 'пустые ipset’ы',
    'blacklist.boot': 'блок-листы пропадут после перезагрузки',
    'blacklist.legacy': 'осталась старая цепочка rugov',
    'tune.bbr': 'нет BBR (тюнинг не применён)',
    'tune.qdisc': 'qdisc не fq',
    'tune.forward': 'выключен ip_forward',
    'conntrack.high': 'conntrack почти заполнен',
    'docker.inactive': 'docker не работает',
    'node.compose': 'нет compose remnanode',
    'node.secret': 'нет SECRET_KEY у remnanode',
    'node.volumes': 'remnanode без нужных томов',
    'node.port': 'NODE_PORT никто не слушает',
    'node.container': 'контейнер remnanode не работает',
    'node.restarts': 'remnanode часто перезапускается',
    'node.pending_recreate': 'remnanode на старом образе',
    'cert.missing': 'нет сертификата',
    'cert.expiring': 'сертификат скоро истечёт',
    'cert.domain': 'сертификат не на тот домен',
    'geo.timer': 'не работает обновление geo',
    'geo.failed': 'обновление geo упало',
    'geo.missing': 'нет geo-файлов',
    'geo.stale': 'geo-файлы устарели',
    'svc.down': 'сервис из fleet.yaml лежит',
    'svc.missing': 'сервиса из fleet.yaml нет на сервере',
    'panel.missing': 'нет ноды в панели',
    'panel.disconnected': 'панель не видит ноду',
    'panel.disabled': 'нода выключена в панели',
};

const CRIT_CODES = new Set([
    'reach',
    'disk.full',
    'fw.missing',
    'fw.inactive',
    'fw.exposed',
    'fw.default_in',
    'fw.public_mgmt',
    'ts.down',
    'ssh.password',
    'docker.inactive',
    'node.compose',
    'node.secret',
    'node.container',
    'svc.down',
    'panel.disconnected',
    'cert.expiring',
]);

const num = (s: unknown) => parseFloat(String(s ?? '').replace(/[^\d.]/g, ''));
const pct = (s: unknown) => {
    const v = num(s);
    if (!Number.isFinite(v)) return '';
    const t = `${v}%`;
    return v >= 90 ? c.red(t) : v >= 80 ? c.yellow(t) : t;
};

type Row = Record<string, unknown>;
interface Col {
    head: string;
    get: (r: Row) => string;
    /** width is taken from the plain text; the cell may carry colour */
    min?: number;
    /** longer values are cut with … */
    max?: number;
    flex?: boolean;
    right?: boolean;
}

function stateCell(r: Row): string {
    const s = String(r.state ?? '');
    if (s === 'UNREACHABLE') return c.red('✖ недоступен');
    if (s === 'crit') return c.red('● крит');
    if (s === 'warn') return c.yellow('● внимание');
    if (s === 'ok' || s === 'info') return c.green('● ok');
    if (s === 'not in fleet.yaml') return c.gray('○ нет в fleet.yaml');
    if (s === 'offline') return c.gray('○ не в сети');
    return s;
}

/** "fw.public_port fw.public_port apt.security" → "apt.security, fw.public_port×2", critical first. */
export function collapseIssues(s: unknown): string[] {
    const counts = new Map<string, number>();
    for (const code of String(s ?? '')
        .split(/\s+/)
        .filter(Boolean))
        counts.set(code, (counts.get(code) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => Number(CRIT_CODES.has(b[0])) - Number(CRIT_CODES.has(a[0])) || a[0].localeCompare(b[0])).map(([k, n]) => (n > 1 ? `${k}×${n}` : k));
}

const tailnetOnly = (r: Row) => r.state === 'not in fleet.yaml' || r.state === 'offline';

/** Problems of one host as coloured tokens: its own codes (common ones left out), or the reason it is unreachable. */
function issueTokens(r: Row, common: Set<string> = new Set()): string[] {
    // the Russian reason is enough in the table; the raw ssh line stays in mia call fleet_status --json
    if (r.state === 'UNREACHABLE' || r.error) return [c.red(String(r.error ?? 'нет ответа').split(' — ')[0])];
    const all = collapseIssues(r.issues);
    const own = all.filter((x) => !common.has(x.replace(/×\d+$/, '')));
    if (!own.length) return [all.length ? c.gray('только общие') : c.green('—')];
    return own.map((x) => (CRIT_CODES.has(x.replace(/×\d+$/, '')) ? c.red(x) : c.yellow(x)));
}

/** As many tokens as fit into w, the rest counted as «+N» — one line per host, never wrapped. */
function fitTokens(tokens: string[], w: number): string {
    const sep = c.gray(', ');
    for (let k = tokens.length; k > 0; k--) {
        const s = tokens.slice(0, k).join(sep) + (k < tokens.length ? ` ${c.gray(`+${tokens.length - k}`)}` : '');
        if (strip(s).length <= w) return s;
    }
    return tokens.length > 1 ? c.gray(`+${tokens.length}`) : (tokens[0] ?? '');
}

const COLS: Col[] = [
    { head: 'хост', get: (r) => c.bold(String(r.host ?? '')) + (r.title ? ' ' + c.gray(String(r.title)) : ''), max: 30 },
    { head: 'состояние', get: stateCell },
    { head: 'аптайм', get: (r) => String(r.up ?? ''), right: true },
    {
        head: 'нагрузка',
        right: true,
        get: (r) => {
            const l = num(r.load);
            const cpu = num(r.cpu);
            if (!Number.isFinite(l)) return '';
            const t = Number.isFinite(cpu) ? `${l}/${cpu}` : `${l}`;
            const k = Number.isFinite(cpu) && cpu ? l / cpu : 0;
            return k >= 1 ? c.red(t) : k >= 0.7 ? c.yellow(t) : t;
        },
    },
    { head: 'память', get: (r) => pct(r.mem), right: true },
    { head: 'диск', get: (r) => pct(r.disk), right: true },
    {
        head: 'темп.',
        right: true,
        get: (r) => {
            const t = num(r.temp);
            if (!Number.isFinite(t)) return '';
            const s = `${t}°`;
            return t >= 85 ? c.red(s) : t >= 70 ? c.yellow(s) : s;
        },
    },
    {
        head: 'обновл.',
        get: (r) => {
            const [all, sec] = String(r.updates ?? '').split('/');
            if (!all) return '';
            const s = num(sec);
            return Number.isFinite(s) && s > 0 ? `${all} ${c.yellow(`(${s})`)}` : all;
        },
    },
    { head: 'ребут', get: (r) => (r.reboot ? c.yellow('нужен') : '') },
    {
        head: 'нода',
        get: (r) => {
            const s = String(r.node ?? '');
            if (!s) return '';
            return s === 'running' ? c.green('✓') : c.red(s === 'absent' ? 'нет' : s);
        },
    },
    {
        head: 'серт.',
        right: true,
        get: (r) => {
            const s = String(r.cert ?? '');
            if (!s || s === '-') return s ? c.gray('—') : '';
            const d = num(s);
            const t = `${d} дн`;
            return d < 14 ? c.red(t) : d < 30 ? c.yellow(t) : t;
        },
    },
    {
        head: 'tailscale',
        get: (r) => {
            const s = String(r.ts ?? '');
            if (!s) return '';
            if (s === 'Running') return c.green('✓') + (r.tsKey ? ` ${c.yellow(`ключ ${String(r.tsKey).replace(/d$/, ' дн').replace('EXPIRED', 'истёк')}`)}` : '');
            const since = s.match(/offline(?: since (\d{4}-\d{2}-\d{2}))?/);
            if (since) {
                const days = since[1] ? Math.max(0, Math.floor((Date.now() - Date.parse(since[1])) / 86_400_000)) : undefined;
                return c.gray(`не в сети${days !== undefined ? ` ${days} дн` : ''}`);
            }
            return /online/.test(s) ? c.gray('в сети') : c.red(s);
        },
    },
    {
        head: 'панель',
        get: (r) => {
            if (!r.panel) return '';
            const [state, users] = String(r.panel).split(' ');
            const n = users ? ` ${users.replace(/u$/, '')}` : '';
            if (state === 'connected') return `${c.green('✓')}${n}`;
            if (state === 'disabled') return c.gray(`выкл.${n}`);
            if (state === 'connecting') return c.yellow(`подключ.${n}`);
            return c.red(`нет связи${n}`);
        },
    },
    {
        head: 'проблемы',
        get: (r) => issueTokens(r).join(c.gray(', ')),
        flex: true,
        min: 20,
    },
];

const cut = (s: string, w: number) => clipVisible(s, w, false);

const pad = (s: string, w: number, right = false) => {
    const n = Math.max(0, w - strip(s).length);
    return right ? ' '.repeat(n) + s : s + ' '.repeat(n);
};

interface GridCol {
    head: string;
    right?: boolean;
}

/** Columns split by │, a ─┼─ rule under the header; every value fits its width (cut with …). */
export function grid(cols: GridCol[], widths: number[], rows: string[][]): string[] {
    const bar = c.gray('│');
    const line = (vals: string[]) =>
        vals
            .map((v, i) => pad(cut(v, widths[i]), widths[i], cols[i].right))
            .join(` ${bar} `)
            .trimEnd();
    return [line(cols.map((col) => c.bold(col.head))), c.gray(widths.map((w) => '─'.repeat(w)).join('─┼─')), ...rows.map(line)];
}

/** grid() width for these column widths. */
const gridWidth = (widths: number[]) => widths.reduce((a, w) => a + w, 0) + 3 * Math.max(0, widths.length - 1);

function onlineCell(r: Row): string {
    if (r.state !== 'offline') return c.green('● в сети');
    const since = String(r.ts ?? '').match(/since (\d{4}-\d{2}-\d{2})/);
    const days = since ? Math.max(0, Math.floor((Date.now() - Date.parse(since[1])) / 86_400_000)) : undefined;
    return c.gray(`○ не в сети${days !== undefined ? ` ${days} дн` : ''}`);
}

function seenCell(r: Row): string {
    if (r.error) return c.yellow(String(r.error).split(' — ')[0]);
    if (r.up !== undefined) {
        const bits = [c.green('ssh ✓'), `аптайм ${r.up}`, r.load !== undefined ? `нагрузка ${r.load}/${r.cpu ?? '?'}` : '', r.disk ? `диск ${pct(r.disk)}` : '', r.updates ? `обновл. ${r.updates}` : ''];
        return bits.filter(Boolean).join(c.gray(' · '));
    }
    return c.gray(r.state === 'offline' ? '—' : 'не linux — ssh не пробовали');
}

/** fleet_status for a person: fleet hosts one line each, split by │, then the tailnet devices that fleet.yaml does not know. */
export function statusTable(
    data: {
        rows: Row[];
        summary?: Record<string, number>;
        panel?: string;
        tailnet?: string;
        hint?: string;
    },
    width = process.stdout.columns || 160,
): string {
    const rows = data.rows.filter((r) => !tailnetOnly(r));
    const extra = data.rows.filter(tailnetOnly);

    // what most of the fleet shares goes above the table once instead of on every line
    const reach = rows.filter((r) => r.state !== 'UNREACHABLE' && !r.error);
    const holders = new Map<string, string[]>();
    for (const r of reach)
        for (const code of new Set(
            String(r.issues ?? '')
                .split(/\s+/)
                .filter(Boolean),
        ))
            holders.set(code, [...(holders.get(code) ?? []), String(r.host)]);
    const common = new Set(reach.length >= 4 ? [...holders].filter(([, hs]) => hs.length >= Math.max(3, Math.ceil(reach.length / 2))).map(([k]) => k) : []);

    let cols = COLS.filter((col) => col.flex || rows.some((r) => strip(col.get(r)) !== ''));
    const measure = (list: Col[]) => list.map((col) => Math.min(col.max ?? Infinity, Math.max(col.head.length, ...rows.map((r) => strip(col.flex ? issueTokens(r, common).join(', ') : col.get(r)).length))));
    // a narrow terminal loses the least important columns first; the problems column always stays
    // (problems keep up to 32 characters before anything else goes)
    for (const drop of ['аптайм', 'ребут', 'темп.', 'серт.', 'панель', 'tailscale', 'нода', 'обновл.', 'память']) {
        const w = measure(cols);
        if (gridWidth(w.map((x, i) => (cols[i].flex ? Math.min(x, 32) : x))) <= width) break;
        cols = cols.filter((col) => col.head !== drop);
    }
    const widths = measure(cols);
    const fi = cols.findIndex((col) => col.flex);
    if (fi >= 0) widths[fi] = Math.max(cols[fi].min ?? 10, Math.min(widths[fi], width - gridWidth(widths.map((w, i) => (i === fi ? 0 : w)))));
    const out: string[] = [];
    if (rows.length) {
        out.push(
            ...grid(
                cols,
                widths,
                rows.map((r) => cols.map((col, i) => (i === fi ? fitTokens(issueTokens(r, common), widths[fi]) : col.get(r)))),
            ),
        );
        const has = (h: string) => cols.some((col) => col.head === h);
        const notes = [has('нагрузка') && 'нагрузка — load за 5 мин / ядер', has('обновл.') && 'обновл. — ждут установки (в скобках security)', has('панель') && 'панель — связь и пользователей онлайн'].filter(Boolean);
        if (notes.length) out.push(c.gray(notes.join(' · ')));
    }

    if (data.summary) {
        const s = data.summary;
        const part = (label: string, v: number | undefined, colour: (x: string) => string) => (v ? colour(`${label} ${v}`) : c.gray(`${label} 0`));
        out.push(
            '',
            [
                c.bold(`всего ${s.hosts}`),
                part('ok', s.ok, c.green),
                part('внимание', s.warn, c.yellow),
                part('крит', s.crit, c.red),
                part('недоступны', s.unreachable, c.red),
                ...(s.tailnetOnly !== undefined ? [part('только в tailnet', s.tailnetOnly, c.gray)] : []),
            ].join(c.gray('  ·  ')),
        );
    }
    const svc = [data.panel && `панель: ${data.panel}`, data.tailnet && `tailnet: ${data.tailnet}`].filter(Boolean) as string[];
    if (svc.length) out.push(c.gray(svc.join('   ')));

    const colour = (k: string) => (CRIT_CODES.has(k) ? c.red(k) : c.yellow(k));
    if (common.size) {
        out.push('', `${c.bold('Общее для большинства')} ${c.gray('(в таблице не повторяется):')}`);
        const list = [...common].sort((a, b) => Number(CRIT_CODES.has(b)) - Number(CRIT_CODES.has(a)) || a.localeCompare(b));
        const kw = Math.max(...list.map((k) => k.length));
        const mw = Math.max(...list.map((k) => (CODE_RU[k] ?? k).length));
        for (const k of list) {
            const hs = holders.get(k)!;
            const without = reach.filter((r) => !hs.includes(String(r.host))).map((r) => String(r.host));
            const who = !without.length ? 'у всех' : without.length <= 5 ? `у всех, кроме ${without.join(', ')}` : `у ${hs.length} из ${reach.length}`;
            out.push(`  ${pad(colour(k), kw)}  ${pad(CODE_RU[k] ?? k, mw)}  ${c.gray(who)}`);
        }
    }
    const used = [...new Set(rows.flatMap((r) => (r.state === 'UNREACHABLE' ? [] : collapseIssues(r.issues).map((x) => x.replace(/×\d+$/, '')))))].filter((k) => !common.has(k)).sort();
    if (used.length) {
        out.push('', c.bold('Что значат коды:'));
        const items = used.map((k) => `${colour(k)} ${c.gray('—')} ${CODE_RU[k] ?? k}`);
        const colW = Math.max(...items.map((x) => strip(x).length)) + 3;
        const per = Math.max(1, Math.floor((width + 3) / colW));
        for (let i = 0; i < items.length; i += per)
            out.push(
                `  ${items
                    .slice(i, i + per)
                    .map((x) => pad(x, colW))
                    .join('')
                    .trimEnd()}`,
            );
    }
    if (rows.length) out.push(c.gray('Подробно по хосту: mia audit <хост>'));

    if (extra.length) {
        const sorted = [...extra].sort((a, b) => Number(a.state === 'offline') - Number(b.state === 'offline') || String(a.host).localeCompare(String(b.host)));
        const tcols = [{ head: 'устройство' }, { head: 'сеть' }, { head: 'ОС' }, { head: 'что видно' }];
        const cells = sorted.map((r) => [String(r.host ?? ''), onlineCell(r), String(r.os ?? String(r.ts ?? '').replace(/^(online|offline( since \S+)?)\s*/, '') ?? ''), seenCell(r)]);
        const tw = tcols.map((col, i) => Math.max(col.head.length, ...cells.map((row) => strip(row[i]).length)));
        tw[0] = Math.min(tw[0], 28);
        tw[3] = Math.max(10, Math.min(tw[3], width - gridWidth(tw.slice(0, 3)) - 3));
        out.push('', `${c.bold('Устройства tailnet, которых нет в fleet.yaml')} ${c.gray(`(${extra.length})`)}`, ...grid(tcols, tw, cells));
        out.push(c.gray('Добавить в fleet.yaml: mia discover — даст готовые записи, после этого у них будет полный аудит.'));
    }
    return out.join('\n');
}
