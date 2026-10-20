import readline from 'node:readline/promises';
import { Writable } from 'node:stream';
import { z } from 'zod';
import { c, hlYaml, strip } from './color.js';
import { Config } from './config.js';
import { Ctx } from './core/ctx.js';
import { ScenarioEngine } from './core/scenario.js';
import { SECRETS, loadSecrets } from './core/secrets.js';
import { SCENARIOS } from './scenarios/index.js';
import { arrowsAvailable, Cancelled, Choice, keyTTY, PickOpts, PickResult, pickTTY } from './select.js';
import { Next, nextActions } from './next.js';
import { HIDDEN, KEYWORDS, PARAM_RU, TITLES } from './labels.js';

export { TITLES };
import * as setup from './setup.js';
import { registry } from './tools/helpers.js';
import { ago, argsLine, cmdLine, crumb, recent, remember, spin, sym } from './tui.js';
import { PARAMS, callTool, confirm, decidePlan, firstSentence, plural, riskOf, showResult, walk, yamlOut } from './ui.js';




type Item =
    /** ask: parameters asked even when they have a default (where to reboot is never «all» by accident) */
    | { kind: 'tool'; tool: string; preset?: Record<string, unknown>; title?: string; ask?: string[] }
    | { kind: 'scenario'; scenario: string; title: string }
    | { kind: 'resume'; title: string }
    | { kind: 'setup'; op: SetupOp; title: string }
    | { kind: 'section'; section: string; title: string }
    | { kind: 'sections'; title: string }
    | { kind: 'alltools'; title: string };

export type SetupOp = 'wizard' | 'settings' | 'check' | 'hosts' | 'host-add' | 'host-tailnet' | 'host-edit' | 'host-toggle' | 'host-remove';

const t = (tool: string, preset?: Record<string, unknown>, title?: string, ask?: string[]): Item => ({ kind: 'tool', tool, preset, title, ask });

const MENU: Array<{ title: string; items: Item[] }> = [
    {
        title: 'Проверки и диагностика',
        items: [
            t('fleet_audit'),
            t('tailnet_devices'),
            t('host_inspect'),
            t('host_logs'),
            t('host_ports'),
            t('host_firewall'),
            t('host_docker'),
            t('host_net_check'),
            t('host_connections'),
            t('tuning_status'),
            t('host_file_read'),
            t('dns_records'),
            t('gitea_runners'),
            t('beszel_systems'),
            t('fleet_discover'),
            t('fleet_hosts'),
        ],
    },
    {
        title: 'Перенос и ранбуки',
        items: [
            { kind: 'scenario', scenario: 'fleet_update', title: 'Обновления флота по одному хосту' },
            { kind: 'scenario', scenario: 'xray_rules', title: 'Правила маршрутизации xray' },
            { kind: 'resume', title: 'Продолжить начатый ранбук' },
            t('host_copy'),
            t('repo_script'),
        ],
    },
    {
        title: 'Обслуживание серверов',
        items: [
            t('remnanode_update'),
            t('service_action'),
            t('apt_upgrade'),
            t('updates_policy'),
            t('host_reboot'),
            t('disk_cleanup'),
            t('cert_renew'),
            t('geo_update'),
            t('blacklist_update'),
            t('tuning_apply'),
            t('node_bootstrap'),
            t('job_status'),
            t('gitea_runner_register'),
            t('host_file_edit'),
        ],
    },
    { title: 'Доступ, сеть и DNS', items: [t('dns_change'), t('ufw_rule'), t('fail2ban_unban'), t('host_exec'), t('tailnet_device_remove'), t('gitea_runner_remove'), t('beszel_system_edit')] },
    { title: 'Изменения и журнал', items: [t('fleet_changes'), t('fleet_snapshot'), t('snapshots_list'), t('journal_list')] },
    {
        title: 'Дом и медиа',
        items: [t('host_services_discover'), t('jellyfin_status'), t('jellyfin_library_add_path'), t('jellyfin_library_create'), t('jellyfin_scan'), t('jellyfin_task_run'), t('tdarr_status'), t('tdarr_library_add'), t('tdarr_scan'), t('tdarr_pause')],
    },
    {
        title: 'Настройка: ключи, адреса, хосты',
        items: [
            { kind: 'setup', op: 'wizard', title: 'Всё по порядку: ключи, адреса, хосты' },
            { kind: 'setup', op: 'settings', title: 'Ключи и адреса сервисов' },
            { kind: 'setup', op: 'check', title: 'Проверить ключи (живые запросы)' },
            { kind: 'setup', op: 'hosts', title: 'Хосты: список' },
            { kind: 'setup', op: 'host-add', title: 'Хосты: добавить' },
            { kind: 'setup', op: 'host-tailnet', title: 'Хосты: добавить из tailnet' },
            { kind: 'setup', op: 'host-edit', title: 'Хосты: изменить' },
            { kind: 'setup', op: 'host-toggle', title: 'Хосты: отключить или включить' },
            { kind: 'setup', op: 'host-remove', title: 'Хосты: удалить из fleet.yaml' },
        ],
    },
    { title: 'Все инструменты по имени', items: [{ kind: 'alltools', title: 'Все инструменты' }] },
];

/** The main menu: what is done most, one Enter to a plan; everything else is a search or a section away. */
const QUICK: Item[] = [
    t('fleet_status', { target: 'all' }, 'Статус всего флота'),
    t('apt_upgrade', { target: 'all' }, 'Обновить пакеты на всех серверах'),
    t('remnanode_update', { target: 'role:remnanode' }, 'Обновить remnanode на всех нодах'),
    t('fleet_audit', { target: 'all' }, 'Аудит всех серверов'),
    t('host_logs', {}, 'Логи сервера…'),
    t('host_reboot', {}, 'Перезагрузить…', ['target']),
    { kind: 'section', section: 'Перенос и ранбуки', title: 'Ранбуки: правила xray, обновления…' },
    { kind: 'section', section: 'Настройка: ключи, адреса, хосты', title: 'Настройка: ключи, адреса, хосты…' },
    { kind: 'sections', title: 'Все действия по разделам…' },
];


/** stdout that can stop echoing (secret input). */
class MaskedOut extends Writable {
    muted = false;
    _write(chunk: Buffer, _enc: BufferEncoding, cb: () => void) {
        if (!this.muted) process.stdout.write(chunk);
        cb();
    }
}

type Ask = (q: string, opts?: { initial?: string }) => Promise<string>;
type Choose = (title: string, items: Choice[], opts?: PickOpts) => Promise<number | undefined>;
type ChooseMany = (title: string, items: Choice[], checked: number[]) => Promise<number[] | undefined>;
type PickAny = (title: string, items: Choice[], opts?: PickOpts) => Promise<PickResult>;
type Deps = { ctx: Ctx; engine: ScenarioEngine; config: Config; ask: Ask; askSecret: (q: string) => Promise<string>; choose: Choose; chooseMany: ChooseMany; pickAny: PickAny };

/** What `mia setup`, `mia update`, `mia <слова>` open straight away. */
export type Start = { setup: SetupOp } | { tool: string; preset?: Record<string, unknown>; ask?: string[] } | { search: string };

export async function startConsole(deps: { ctx: Ctx; engine: ScenarioEngine; config: Config }, start?: Start, once = false) {
    const { ctx, config } = deps;
    const out = new MaskedOut();
    const words = () => {
        const inv = ctx.inventory();
        return ['all', 'role:remnanode', 'role:edge', 'role:panel', 'role:docker', ...inv.hosts.keys(), ...inv.groups.keys(), ...new Set([...inv.hosts.values()].flatMap((h) => h.tags.map((x) => `tag:${x}`)))];
    };
    let ac = new AbortController();
    const makeRl = (history: string[] = []) => {
        const r = readline.createInterface({
            input: process.stdin,
            output: out,
            terminal: true,
            history,
            completer: (line: string): [string[], string] => {
                const last = line.split(/[,\s]/).pop() ?? '';
                const hits = words().filter((w) => w.startsWith(last.replace(/^!/, '')));
                return [hits.map((h) => line.slice(0, line.length - last.length) + (last.startsWith('!') ? '!' : '') + h), line];
            },
        });
        r.on('SIGINT', () => ac.abort());
        return r;
    };
    let rl = makeRl();
    // a question may come prefilled with the current value: edit in place, Enter keeps it
    const ask: Ask = async (q, opts = {}) => {
        ac = new AbortController();
        try {
            const answer = rl.question(q, { signal: ac.signal });
            if (opts.initial) rl.write(opts.initial);
            return await answer;
        } catch {
            throw new Cancelled();
        }
    };
    const askSecret = async (q: string): Promise<string> => {
        process.stdout.write(q);
        out.muted = true;
        try {
            return await ask('');
        } finally {
            out.muted = false;
            process.stdout.write('\n');
        }
    };
    // arrows need stdin in raw mode: the line reader steps aside while a menu is open
    const raw = async (title: string, items: Choice[], opts: PickOpts) => {
        const history = [...((rl as unknown as { history?: string[] }).history ?? [])];
        rl.close();
        try {
            const r = await pickTTY(title, items, opts);
            if (r.kind === 'cancel') throw new Cancelled();
            return r;
        } finally {
            rl = makeRl(history);
        }
    };
    const pickAny: PickAny = async (title, items, opts = {}) => {
        if (arrowsAvailable()) return raw(title, items, opts);
        if (opts.multi) {
            const got = await numberedMany(ask, title, items, opts.checked ?? []);
            return got ? { kind: 'many', indexes: got } : { kind: 'back' };
        }
        const n = await numbered(ask, title, [...items, ...(opts.searchOnly ?? [])], opts);
        return typeof n === 'string' ? { kind: 'text', text: n } : n === undefined ? { kind: 'back' } : { kind: 'select', index: n };
    };
    const choose: Choose = async (title, items, opts = {}) => {
        const r = await pickAny(title, items, opts);
        return r.kind === 'select' ? r.index : undefined;
    };
    const chooseMany: ChooseMany = async (title, items, checked) => {
        const r = await pickAny(title, items, { multi: true, checked });
        return r.kind === 'many' ? r.indexes : undefined;
    };
    const d: Deps = { ...deps, ask, askSecret, choose, chooseMany, pickAny };
    const guard = async (fn: () => Promise<Outcome | void | unknown>): Promise<Outcome | undefined> => {
        try {
            const o = await fn();
            return o && typeof o === 'object' && 'done' in (o as object) ? (o as Outcome) : undefined;
        } catch (e) {
            if (e instanceof Cancelled) return undefined;
            console.log(`${sym.fail} ${c.red(e instanceof Error ? e.message : String(e))}`);
            return { done: true };
        }
    };
    // a single key on a terminal (the line reader steps aside), a line otherwise
    const key = async (keys: string[]): Promise<string> => {
        if (!arrowsAvailable()) return (await ask('> ')).trim().toLowerCase();
        const history = [...((rl as unknown as { history?: string[] }).history ?? [])];
        rl.close();
        try {
            const k = await keyTTY(keys);
            if (k === 'cancel') throw new Cancelled();
            return k;
        } finally {
            rl = makeRl(history);
        }
    };
    // what the last status suggested, until something is changed
    let suggest: Next[] = [];
    let lastStatus: { at: number; summary: Record<string, number> } | undefined;
    /** Results stay on screen until a key: «Дальше» — the fixes they suggest, «п» — again with other parameters. */
    const after = async (o: Outcome | undefined): Promise<void> => {
        while (o) {
            if (o.tool === 'fleet_status' && o.data && typeof o.data === 'object' && 'summary' in (o.data as object)) lastStatus = { at: Date.now(), summary: (o.data as { summary: Record<string, number> }).summary };
            const next = o.tool && o.data ? nextActions(o.tool, o.args ?? {}, o.data, (t) => registry.has(t)) : [];
            if (o.tool === 'fleet_status' || o.tool === 'fleet_audit') suggest = next.filter((n) => n.tool !== 'fleet_audit');
            if (o.applied) suggest = [];
            const canEdit = !!o.tool && Object.keys(registry.get(o.tool)?.schema ?? {}).some((k) => !['apply', 'planHash'].includes(k));
            console.log('');
            if (next.length) {
                console.log(c.bold('Дальше:'));
                next.forEach((n, i) => console.log(`  ${c.cyan(String(i + 1))}  ${n.label}${n.hint ? c.gray(`  ${n.hint}`) : ''}`));
            }
            console.log(c.gray(`  ${[canEdit ? 'п — то же с другими параметрами' : '', 'Enter — в меню'].filter(Boolean).join(' · ')}`));
            let k: string;
            try {
                k = await key([...next.map((_, i) => String(i + 1)), ...(canEdit ? ['п', 'g'] : [])]);
            } catch {
                return;
            }
            const i = Number(k) - 1;
            clear();
            if (k === 'п' || k === 'g') o = await guard(() => runTool(o!.tool!, d, {}, { values: o!.args, edit: true }));
            else if (next[i]?.setup) o = await guard(() => runItem({ kind: 'setup', op: next[i].setup!, title: next[i].label }, d, ['Дальше']));
            else if (next[i]?.tool) o = await guard(() => runTool(next[i].tool!, d, next[i].preset ?? {}, { path: ['Дальше'] }));
            else return;
        }
    };
    const everything = () => searchable();

    if (start) {
        const o = await guard(async () => {
            if ('setup' in start) return runItem({ kind: 'setup', op: start.setup, title: 'Настройка' }, d, ['Настройка']);
            if ('tool' in start) return runTool(start.tool, d, start.preset ?? {}, { ask: start.ask });
            const all = everything();
            const r = await pickAny(crumb('поиск'), [], { searchOnly: all.map((x) => x.choice), filter: start.search, footer: config.readonly ? 'режим только чтения: действия, меняющие серверы, не ищутся' : undefined });
            if (r.kind === 'select') return runItem(all[r.index].item, d, all[r.index].path);
        });
        if (once) {
            // a one-shot command (mia update) still offers what follows (a reboot after the update …)
            if (o?.tool && o.data && nextActions(o.tool, o.args ?? {}, o.data, (t) => registry.has(t)).length) await after(o);
            return rl.close();
        }
        await after(o);
    }
    // the cursor comes back to the line picked last (by its text: recent runs shift the numbers)
    let lastLabel = '';
    for (;;) {
        // recent runs, then the frequent actions; typing finds any action, runbook or setting
        const recents = recent(config.stateDir)
            .filter((r) => registry.has(r.tool))
            .slice(0, 3);
        // read-only mode (mia-ro) has no write tools: their lines are not offered
        const quick = available(QUICK);
        const tips = suggest.slice(0, 3);
        const top: Choice[] = [
            ...tips.map((n) => ({ label: `${c.yellow('→')} ${n.label}`, hint: n.hint, keys: n.tool })),
            ...recents.map((r) => ({ label: `${c.cyan('↺')} ${TITLES[r.tool] ?? r.tool}`, hint: `${argsLine(r.args)}${argsLine(r.args) ? ' · ' : ''}${ago(r.at)}`, keys: `${r.tool} ${KEYWORDS[r.tool] ?? ''}` })),
            ...quick.map((it) => ({ label: itemLabel(it), keys: it.kind === 'tool' ? `${it.tool} ${KEYWORDS[it.tool] ?? ''}` : undefined })),
            { label: c.gray('Выход'), keys: 'exit quit выход' },
        ];
        const all = everything();
        clear();
        header(config, ctx, lastStatus);
        let r: PickResult;
        try {
            r = await pickAny(crumb(), top, {
                initial: Math.max(0, top.findIndex((x) => strip(x.label) === lastLabel && !strip(x.label).startsWith('↺')), lastLabel.startsWith('↺') ? 0 : -1),
                numberFrom: tips.length + recents.length,
                searchOnly: all.map((x) => x.choice),
                echo: false,
                footer: [tips.length ? '→ — предложено последним статусом' : '', recents.length ? '↺ — повторить как было (→ — с другими параметрами)' : ''].filter(Boolean).join(' · ') || undefined,
            });
        } catch {
            break;
        }
        if (r.kind !== 'select' || r.index === top.length - 1) break;
        const n = r.index;
        // a search hit leaves the cursor where it was, never on «Выход»
        if (n < top.length) lastLabel = strip(top[n].label);
        const alt = r.kind === 'select' && !!r.alt;
        clear();
        const o = await guard(async () => {
            if (n < tips.length) {
                const t = tips[n];
                if (t.setup) return runItem({ kind: 'setup', op: t.setup, title: t.label }, d, ['предложено']);
                return runTool(t.tool!, d, t.preset ?? {}, { path: ['предложено'], edit: alt });
            }
            const m = n - tips.length;
            if (m < recents.length) return runTool(recents[m].tool, d, {}, { values: recents[m].args, path: ['недавнее'], edit: alt });
            if (m < recents.length + quick.length) return runItem(quick[m - recents.length], d, [], alt);
            const hit = all[n - top.length];
            return runItem(hit.item, d, hit.path, alt);
        });
        await after(o);
    }
    rl.close();
}

/** A clean screen per step (what was there stays in the terminal's scrollback). */
function clear() {
    if (process.stdout.isTTY && !process.env.MIA_NO_CLEAR) process.stdout.write('\x1b[H\x1b[2J');
}

/** What an action left behind, for «Дальше». */
interface Outcome {
    done: true;
    tool?: string;
    args?: Record<string, unknown>;
    data?: unknown;
    applied?: boolean;
}

/** Every menu item and every tool, for typing in the main menu. */
function searchable(): Array<{ item: Item; path: string[]; choice: Choice }> {
    const out: Array<{ item: Item; path: string[]; choice: Choice }> = [];
    const seen = new Set<string>();
    const kw = (it: Item) => (it.kind === 'tool' ? `${it.tool} ${KEYWORDS[it.tool] ?? ''}` : it.kind === 'scenario' ? it.scenario : undefined);
    for (const it of available(QUICK)) if (it.kind === 'tool') out.push({ item: it, path: [], choice: { label: itemLabel(it), hint: 'частое', keys: kw(it) } });
    for (const m of MENU) {
        for (const it of available(m.items)) {
            if (it.kind === 'alltools') continue;
            const label = itemLabel(it);
            if (it.kind === 'tool') seen.add(it.tool);
            out.push({ item: it, path: [m.title], choice: { label, hint: m.title, keys: kw(it) } });
        }
    }
    for (const name of [...registry.keys()].sort()) {
        if (seen.has(name) || name.startsWith('scenario_')) continue;
        const it: Item = { kind: 'tool', tool: name };
        out.push({ item: it, path: ['Все инструменты'], choice: { label: itemLabel(it), hint: 'Все инструменты', keys: `${name} ${KEYWORDS[name] ?? ''}` } });
    }
    return out;
}

function available(items: Item[]): Item[] {
    return items.filter((i) => i.kind !== 'tool' || registry.has(i.tool));
}

function itemLabel(it: Item): string {
    if (it.kind !== 'tool') return it.title;
    const write = !registry.get(it.tool)!.readonly;
    return `${it.title ?? TITLES[it.tool] ?? firstSentence(registry.get(it.tool)!.description, 90)}${write ? c.yellow(' ✎') : ''}`;
}

/** Two lines at most: what mia can reach, the fleet as the last status saw it, what to set up. */
function header(config: Config, ctx: Ctx, last?: { at: number; summary: Record<string, number> }) {
    const inv = ctx.inventory();
    const sec = loadSecrets({ ...process.env });
    const need = SECRETS.filter((s) => !s.optional);
    const missing = need.filter((s) => sec.states.find((x) => x.name === s.name)?.source === 'missing');
    const off = [!config.panel && 'панель', !config.tailscaleApi && 'Tailscale API', !config.remnawaveMcp && 'mcp-remnawave'].filter(Boolean);
    const fleet = last
        ? [
              `${sym.ok} ${last.summary.ok ?? 0}`,
              last.summary.warn ? `${sym.warn} ${last.summary.warn}` : '',
              last.summary.crit ? `${c.red('●')} ${last.summary.crit} крит` : '',
              last.summary.unreachable ? `${sym.fail} ${last.summary.unreachable} недоступно` : '',
              c.gray(`статус ${ago(new Date(last.at).toISOString())}`),
          ]
              .filter(Boolean)
              .join('  ')
        : c.gray('статус ещё не смотрели');
    console.log(`${c.bold(c.cyan('mia'))}  ${c.bold(String(inv.hosts.size))} ${plural(inv.hosts.size, 'хост', 'хоста', 'хостов')}  ${fleet}${config.readonly ? `  ${sym.warn} ${c.yellow('только чтение')}` : ''}`);
    const notes = [missing.length ? `не задано ${missing.length} из ${need.length} ключей → «Настройка»` : '', off.length && !missing.length ? `нет: ${off.join(', ')}` : ''].filter(Boolean);
    if (config.demo) console.log(c.yellow('ДЕМО: выдуманный флот — жать можно всё, настоящие серверы не трогаются'));
    else if (notes.length) console.log(c.gray(notes.join(' · ')));
    if (sec.warning) console.log(`${sym.fail} ${c.red(sec.warning)}`);
}

async function pick(choose: Choose, title: string, items: Item[]): Promise<Item | undefined> {
    const choices = items.map((it) => ({ label: itemLabel(it), keys: it.kind === 'tool' ? it.tool : undefined }));
    const hasWrite = items.some((it) => it.kind === 'tool' && !registry.get(it.tool)!.readonly);
    const n = await choose(crumb(title), choices, { echo: false, footer: hasWrite ? '✎ — меняет серверы: сначала план, потом «Выполнить?» (Enter — да)' : undefined });
    return n === undefined ? undefined : items[n];
}

/** The same menus without arrows (no terminal, or MIA_NUMBERS=1): a number or a name, Enter — back. */
async function numbered(ask: Ask, title: string, items: Choice[], opts: PickOpts = {}): Promise<number | string | undefined> {
    console.log(c.bold(strip(title)));
    items.forEach((it, i) => console.log(`  ${c.cyan(String(i + 1).padStart(2))}  ${it.label}${it.hint ? `  ${c.gray(it.hint)}` : ''}`));
    if (opts.footer) console.log(c.gray(`  ${opts.footer}`));
    for (;;) {
        const a = (await ask(c.gray('номер или имя, Enter — назад > '))).trim();
        if (!a) return undefined;
        const byNum = Number(a) - 1;
        if (Number.isInteger(byNum) && items[byNum]) return byNum;
        const byName = items.findIndex((it) => strip(it.label).trim().toLowerCase() === a.toLowerCase() || it.keys?.split(/\s+/).includes(a));
        if (byName >= 0) return byName;
        if (opts.freeText) return a;
        console.log(c.yellow('Нет такого пункта'));
    }
}

async function numberedMany(ask: Ask, title: string, items: Choice[], checked: number[]): Promise<number[] | undefined> {
    console.log(c.bold(strip(title)));
    items.forEach((it, i) => console.log(`  ${c.cyan(String(i + 1).padStart(2))}  ${checked.includes(i) ? '◉' : '◯'} ${it.label}${it.hint ? `  ${c.gray(it.hint)}` : ''}`));
    const a = (await ask(c.gray('номера через запятую (Enter — как отмечено, «-» — ничего) > '))).trim();
    if (!a) return checked;
    if (a === '-') return [];
    return a
        .split(/[,\s]+/)
        .map((x) => Number(x) - 1)
        .filter((i) => Number.isInteger(i) && items[i]);
}

async function runItem(item: Item, d: Deps, path: string[], edit = false): Promise<Outcome | undefined> {
    if (item.kind === 'tool') return runTool(item.tool, d, item.preset, { ask: item.ask, path, edit });
    if (item.kind === 'section' || item.kind === 'sections') {
        const m = item.kind === 'section' ? MENU.find((x) => x.title === item.section) : MENU[(await d.choose(crumb('Все действия'), MENU.map((x) => ({ label: x.title, hint: `${available(x.items).length}` })))) ?? -1];
        if (!m) return;
        const items = available(m.items);
        const it = items.length === 1 ? items[0] : await pick(d.choose, m.title, items);
        if (!it) return undefined;
        clear();
        return runItem(it, d, [m.title]);
    }
    if (item.kind === 'scenario') {
        const def = SCENARIOS.get(item.scenario)!;
        console.log(`\n${crumb(...path, item.title)}\n${c.gray(def.description)}`);
        const params = await paramsCard(def.params, {}, d, { go: '▶ Запустить ранбук', path: [...path, item.title] });
        if (!params) return;
        const adv = await spin('запускаю ранбук', () => d.engine.start(item.scenario, params));
        await walk(d.engine, adv, d.ask);
        return { done: true };
    }
    if (item.kind === 'resume') {
        const runs = d.engine.runs().filter((r) => !r.finished);
        if (!runs.length) {
            console.log(`${sym.skip} ${c.gray('Незавершённых прогонов нет.')}`);
            return { done: true };
        }
        const n = await d.choose(
            crumb(...path, 'Какой прогон продолжить?'),
            runs.map((r) => ({ label: r.run, hint: `${r.scenario} · шаг ${r.step} · ${ago(r.updatedAt)}` })),
        );
        if (n === undefined) return undefined;
        await walk(d.engine, await spin('восстанавливаю прогон', () => d.engine.resume(runs[n].run)), d.ask);
        return { done: true };
    }
    if (item.kind === 'setup') {
        const io: setup.Io = { ask: d.ask, askSecret: d.askSecret, choose: (t, i, o) => d.choose(crumb(...path, strip(t)), i, o), chooseMany: (t, i, ch) => d.chooseMany(crumb(...path, strip(t)), i, ch), confirm: (q) => confirm(d.ask, q) };
        const env = { config: d.config, ctx: d.ctx };
        const ops: Record<SetupOp, () => Promise<unknown>> = {
            wizard: () => setup.setupWizard(io, env),
            settings: () => setup.editSettings(io, env),
            check: () => setup.checkAll(env),
            hosts: async () => setup.hostsList(env),
            'host-add': () => setup.hostAdd(io, env),
            'host-tailnet': () => setup.hostFromTailnet(io, env),
            'host-edit': () => setup.hostEdit(io, env),
            'host-toggle': () => setup.hostToggle(io, env),
            'host-remove': () => setup.hostRemove(io, env),
        };
        await ops[item.op]();
        return { done: true };
    }
    if (item.kind === 'alltools') {
        const names = [...registry.keys()].filter((n) => !n.startsWith('scenario_')).sort();
        const w = Math.max(...names.map((n) => n.length));
        const i = await d.choose(
            crumb(...path),
            names.map((n) => ({ label: `${n.padEnd(w)} ${registry.get(n)!.readonly ? ' ' : c.yellow('✎')}`, hint: TITLES[n] ?? firstSentence(registry.get(n)!.description, 80) })),
            { footer: '✎ — меняет серверы: сначала план, потом «Выполнить?» (Enter — да)' },
        );
        if (i !== undefined) {
            clear();
            return runTool(names[i], d, {}, { path });
        }
    }
    return undefined;
}

/**
 * The short path: only what is missing is asked (by picking, not typing), then straight to the plan
 * (or the result). Parameters are one key away: «п» at «Выполнить?», → on a menu line.
 */
async function runTool(tool: string, d: Deps, preset: Record<string, unknown> = {}, opts: { values?: Record<string, unknown>; path?: string[]; ask?: string[]; edit?: boolean } = {}): Promise<Outcome | undefined> {
    const spec = registry.get(tool)!;
    const title = TITLES[tool] ?? tool;
    const shape = spec.schema as z.ZodRawShape;
    const planned = 'apply' in shape;
    const path = [...(opts.path ?? []), title];
    console.log(`\n${crumb(...path)} ${c.gray(`(${tool})`)}`);
    const card = (args: Record<string, unknown>) => paramsCard(shape, preset, d, { go: spec.readonly || !planned ? '▶ Выполнить' : '▶ Построить план (ничего не меняется)', values: args, path });
    let args: Record<string, unknown> | undefined = { ...preset, ...Object.fromEntries(Object.entries(opts.values ?? {}).filter(([k]) => k in shape)) };
    args = opts.edit ? await card(args) : await askMissing(shape, args, d, opts.ask ?? []);
    if (!args) return undefined;
    if (spec.readonly || !planned) {
        if (!spec.readonly && !(await confirm(d.ask, `${sym.warn} ${c.yellow('Это действие без холостого прогона. Выполнить?')}`))) {
            console.log(`${sym.skip} ${c.gray('Отменено, ничего не сделано.')}`);
            return { done: true, tool, args };
        }
        const res = await spin('выполняю', () => callTool(tool, args!));
        console.log(res.isError ? `${sym.fail} ${c.red(res.text)}` : showResult(tool, res.data));
        if (!res.isError) remember(d.config.stateDir, tool, args, HIDDEN);
        return { done: true, tool, args, data: res.isError ? undefined : res.data, applied: !spec.readonly };
    }
    // «выполнить на остальных» already said yes to exactly this many hosts
    let approved: number | undefined;
    for (;;) {
        const dry = await spin('строю план — ничего не меняется', () => callTool(tool, { ...args!, apply: false }), () => 'план готов');
        if (dry.isError) {
            console.log(`${sym.fail} ${c.red(dry.text)}`);
            return { done: true, tool, args };
        }
        const plan = dry.data as { planHash?: string; toRun?: number; blocked?: string[] };
        console.log(showPlan(dry.data));
        remember(d.config.stateDir, tool, args, HIDDEN);
        const nothing = !plan.planHash || plan.toRun === 0;
        // blocked only by hosts that do not answer: offer the rest in one Enter
        const dead = (plan.blocked ?? []).filter((b) => /^[^:]+: unreachable:/.test(b)).map((b) => b.split(':')[0]);
        if (plan.blocked?.length && dead.length === plan.blocked.length && 'skipUnreachable' in shape && !args.skipUnreachable) {
            const rest = (plan.toRun ?? 0) - dead.length;
            if (rest > 0 && (await confirm(d.ask, `${sym.warn} Не отвечают: ${c.bold(dead.join(', '))}. Выполнить на остальных ${rest}?`))) {
                args = { ...args, skipUnreachable: true };
                approved = rest;
                continue;
            }
            return { done: true, tool, args };
        }
        if (nothing) console.log(`${sym.ok} ${c.green('Делать нечего: всё уже как надо.')}`);
        else if (plan.blocked?.length) console.log(`${sym.fail} ${c.red('Есть блокеры — выполнить нельзя, пока их не убрать.')}`);
        const risk = riskOf(tool, dry.data);
        const same = approved !== undefined && !plan.blocked?.length && plan.toRun === approved && !risk;
        const answer = nothing || plan.blocked?.length ? await offerParams(d.ask) : same ? 'yes' : await decidePlan(d.ask, risk);
        approved = undefined;
        if (answer === 'params') {
            args = await card(args);
            if (!args) return undefined;
            continue;
        }
        // nothing to do / blocked / «н»: back to the menu at once, nothing to read below the plan
        if (answer === 'no') return undefined;
        const res = await spin('выполняю', () => callTool(tool, { ...args!, apply: true, planHash: plan.planHash }));
        console.log(res.isError ? `${sym.fail} ${c.red(res.text)}` : showApplied(res.data));
        return { done: true, tool, args, data: res.isError ? undefined : res.data, applied: true };
    }
}

/** After «нечего делать» or blockers: Enter — back to the menu, «п» — change the parameters. */
async function offerParams(ask: Ask): Promise<'no' | 'params'> {
    const a = (await ask(c.gray('Enter — в меню · п — поменять параметры ')))
        .trim()
        .toLowerCase();
    return PARAMS.has(a) ? 'params' : 'no';
}

/**
 * Only what the tool cannot do without (and what the menu item insists on) is asked, each by the
 * quickest means: where → a list of the fleet, which host → hosts, which log → that host's services.
 */
async function askMissing(shape: z.ZodRawShape, args: Record<string, unknown>, d: Deps, force: string[]): Promise<Record<string, unknown> | undefined> {
    const out = { ...args };
    for (const [k, raw] of Object.entries(shape)) {
        const t = raw as z.ZodTypeAny;
        if (['apply', 'planHash'].includes(k) || out[k] !== undefined) continue;
        if (t.isOptional() && !force.includes(k)) continue;
        const v = await askSmart(k, t, d, out);
        if (v === undefined) return undefined;
        out[k] = v;
    }
    return out;
}

async function askSmart(name: string, t: z.ZodTypeAny, d: Deps, args: Record<string, unknown>): Promise<unknown> {
    const base = unwrap(t);
    if (name === 'target' && base instanceof z.ZodString) return pickTarget(d, name);
    if (name === 'host' && base instanceof z.ZodString) return pickHostName(d);
    if ((name === 'source' || name === 'service') && typeof args.host === 'string' && base instanceof z.ZodString) return pickSource(d, String(args.host), name);
    if (base instanceof z.ZodBoolean) {
        const i = await d.choose(`${c.bold(name)}${PARAM_RU[name] ? c.gray(` — ${PARAM_RU[name]}`) : ''}`, [{ label: 'да' }, { label: 'нет' }], { initial: defaultOf(t) === false ? 1 : 0 });
        return i === undefined ? undefined : i === 0;
    }
    const v = await askOne(name, t, d, true);
    return v === undefined ? defaultOf(t) : v;
}

/** Where to run: everything, all nodes, a group, a tag, hosts (Space for several) or an expression typed in. */
async function pickTarget(d: Deps, name: string): Promise<string | undefined> {
    const inv = d.ctx.inventory();
    const hosts = [...inv.hosts.values()].filter((h) => !h.disabled);
    const count = (n: number) => `${n} ${plural(n, 'хост', 'хоста', 'хостов')}`;
    const opts: Array<{ value: string; choice: Choice }> = [{ value: 'all', choice: { label: 'все серверы', hint: count(hosts.length) } }];
    const nodes = hosts.filter((h) => h.roles.includes('remnanode')).length;
    if (nodes) opts.push({ value: 'role:remnanode', choice: { label: 'все ноды (remnanode)', hint: count(nodes) } });
    for (const [g, members] of inv.groups) opts.push({ value: g, choice: { label: `группа ${g}`, hint: `${count(members.length)}: ${members.slice(0, 6).join(' ')}${members.length > 6 ? ' …' : ''}` } });
    for (const tag of [...new Set(hosts.flatMap((h) => h.tags))].sort()) opts.push({ value: `tag:${tag}`, choice: { label: `тег ${tag}`, hint: count(hosts.filter((h) => h.tags.includes(tag)).length) } });
    for (const h of [...inv.hosts.values()]) opts.push({ value: h.name, choice: { label: h.disabled ? c.gray(`${h.name} (отключён)`) : h.name, hint: [h.address, h.roles.join(',')].join(' · '), keys: h.groups.join(' ') } });
    const r = await d.pickAny(`${c.bold('Где?')} ${c.gray(`(${name})`)}`, opts.map((o) => o.choice), { multi: true, enterPicksCurrent: true, freeText: 'как выражение (nl-*,!nl-3)' });
    if (r.kind === 'text') return r.text;
    if (r.kind !== 'many' || !r.indexes.length) return undefined;
    return r.indexes.map((i) => opts[i].value).join(',');
}

async function pickHostName(d: Deps): Promise<string | undefined> {
    const hosts = [...d.ctx.inventory().hosts.values()];
    const r = await d.pickAny(
        c.bold('Какой сервер?'),
        hosts.map((h) => ({ label: h.disabled ? c.gray(`${h.name} (отключён)`) : h.name, hint: [h.address, h.roles.join(','), h.groups.join(',')].filter(Boolean).join(' · ') })),
        { freeText: 'другой (имя или адрес)' },
    );
    return r.kind === 'select' ? hosts[r.index].name : r.kind === 'text' ? r.text : undefined;
}

/** Logs / services of one host: what fleet.yaml and its roles say runs there. */
async function pickSource(d: Deps, host: string, name: string): Promise<string | undefined> {
    let h;
    try {
        h = d.ctx.inventory().get(host);
    } catch {
        return (await d.ask(`  ${c.bold(name)}: `)).trim() || undefined;
    }
    const items = [...new Set([...h.services.map((s) => s.name), ...(name === 'source' ? [...Object.keys(h.logs), 'journal'] : [])])];
    const r = await d.pickAny(`${c.bold(name === 'source' ? 'Какие логи?' : 'Какой сервис?')} ${c.gray(host)}`, items.map((x) => ({ label: x })), { freeText: 'другое' });
    return r.kind === 'select' ? items[r.index] : r.kind === 'text' ? r.text : undefined;
}

const summaryLine = (parts: Array<[number, string, (s: string) => string]>) =>
    parts
        .filter(([n], i) => n || i === 0)
        .map(([n, label, colour]) => colour(`${label} ${n}`))
        .join(c.gray(' · '));

/** Dry run → readable plan: the counts first, then hosts with the same plan on one line, warnings, blockers. */
export function showPlan(data: unknown): string {
    const d = data as { plan?: Array<Record<string, unknown>>; hosts?: number; toRun?: number; rollout?: { batch: number }; blocked?: string[] };
    if (!Array.isArray(d?.plan)) return yamlOut(data);
    const skips = d.plan.filter((p) => p.skip).length;
    const blocks = d.plan.filter((p) => (p.blockers as string[] | undefined)?.length).length;
    const lines = [
        `${sym.step} ${c.bold('План:')} ${summaryLine([
            [(d.toRun ?? 0) - blocks, 'изменится', c.green],
            [skips, 'пропуск', c.gray],
            [blocks, 'блокеров', c.red],
        ])}${d.rollout ? c.gray(` · по ${d.rollout.batch} за раз, стоп на первой ошибке`) : ''}`,
    ];
    // hosts that will get exactly the same are one line
    const groups = new Map<string, { who: string[]; p: Record<string, unknown> }>();
    for (const p of d.plan) {
        const k = JSON.stringify([p.skip, p.will, p.now, p.after, p.warnings, p.blockers]);
        const g = groups.get(k) ?? { who: [], p };
        g.who.push(String(p.host ?? p.target));
        groups.set(k, g);
    }
    for (const { who, p } of groups.values()) {
        const names = who.length > 6 ? `${who.slice(0, 6).join(', ')} … ещё ${who.length - 6}` : who.join(', ');
        if (p.skip) lines.push(`  ${sym.skip} ${c.gray(`${names} — пропуск: ${p.skip}`)}`);
        else lines.push(`  ${c.green('▸')} ${c.bold(names)} ${c.gray('—')} ${p.will}`);
        // a few hosts get their details, a fleet gets a line each
        const roomy = groups.size <= 2 && who.length === 1;
        if (p.now !== undefined) lines.push(roomy ? hlYaml(yamlIndent(p.now, '      сейчас: ')) : `      ${c.gray('сейчас:')} ${brief(p.now)}`);
        if (p.after !== undefined) lines.push(roomy ? hlYaml(yamlIndent(p.after, '      станет: ')) : `      ${c.gray('станет:')} ${brief(p.after)}`);
        for (const w of (p.warnings as string[] | undefined) ?? []) lines.push(`      ${sym.warn} ${c.yellow(ruWarning(w))}`);
        for (const b of (p.blockers as string[] | undefined) ?? []) lines.push(`      ${sym.fail} ${c.red(b.replace(/^unreachable: (.*?)( — .*)?$/, 'не отвечает: $1'))}`);
    }
    return lines.join('\n');
}

/** The tools warn in English (their JSON is for Claude too): the frequent warnings in Russian for the console. */
export function ruWarning(w: string): string {
    return w
        .replace(/^docker packages are upgraded: all containers restart/, 'обновляется docker: все контейнеры перезапустятся')
        .replace(/(\d+) user\(s\) online on (\S+) will reconnect/, '$1 польз. онлайн на $2 переподключатся')
        .replace(/(\d+) user\(s\) on (\S+) will be disconnected/, '$1 польз. на $2 отключатся')
        .replace(/(\d+) user\(s\) on (\S+) will reconnect/, '$1 польз. на $2 переподключатся')
        .replace(/^(\S+) is not in policy\.publicPorts: fleet_audit will flag it until you add it to fleet\.yaml/, '$1 нет в policy.publicPorts: аудит будет отмечать, пока не добавить в fleet.yaml');
}

/** One line for a host's «now»: scalars as they are, lists as a count and the first names. */
export function brief(v: unknown): string {
    if (v === null || typeof v !== 'object') return String(v);
    if (Array.isArray(v)) return `${v.length}${v.length ? ` (${v.slice(0, 4).map((x) => (typeof x === 'string' ? x.split(' ')[0] : JSON.stringify(x))).join(', ')}${v.length > 4 ? ', …' : ''})` : ''}`;
    return Object.entries(v as Record<string, unknown>)
        .filter(([, x]) => x !== undefined && x !== null && x !== '' && !(Array.isArray(x) && !x.length))
        .map(([k, x]) => (typeof x === 'object' ? `${k}: ${brief(x)}` : `${k} ${x}`))
        .join(c.gray(' · '));
}

/** Long lists of names (packages …) fold to the first ones and a count. */
function fold(v: unknown): unknown {
    if (Array.isArray(v)) return v.length > 8 && v.every((x) => typeof x === 'string') ? [...v.slice(0, 8), `… ещё ${v.length - 8}`] : v.map(fold);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fold(x)]));
    return v;
}

function yamlIndent(raw: unknown, label: string): string {
    const v = fold(raw);
    const text = typeof v === 'string' ? v : JSON.stringify(v).length < 90 ? JSON.stringify(v) : '\n' + yamlOut(v, 30).split('\n').map((l) => '        ' + l).join('\n');
    return `${c.gray(label)}${text}`;
}

export function showApplied(data: unknown): string {
    const d = data as { mode?: string; results?: Array<Record<string, unknown>>; reason?: string; stoppedAt?: string; notRun?: string[] };
    if (!d?.mode) return yamlOut(data);
    const res = d.results ?? [];
    const good = res.filter((r) => r.ok).length;
    const head =
        d.mode === 'applied'
            ? `${sym.ok} ${c.green(c.bold('Выполнено'))} ${summaryLine([[good, 'ok', c.green]])}`
            : d.mode === 'aborted'
              ? `${sym.warn} ${c.yellow(`Не выполнено: ${d.reason}`)}`
              : d.mode === 'nothing-to-do'
                ? `${sym.ok} ${c.green('Делать нечего.')}`
                : `${sym.fail} ${c.red(c.bold(`Остановлено${d.stoppedAt ? ` на ${d.stoppedAt}` : ''}`))} ${summaryLine([
                      [good, 'ok', c.green],
                      [res.length - good, 'ошибок', c.red],
                      [d.notRun?.length ?? 0, 'не запускалось', c.yellow],
                  ])}`;
    const lines = [head];
    for (const r of res) {
        lines.push(`  ${r.ok ? sym.ok : sym.fail} ${c.bold(String(r.host ?? r.target))}${r.ms ? c.gray(` ${Math.round(Number(r.ms) / 100) / 10}s`) : ''}${r.error ? c.red(` — ${r.error}`) : ''}`);
        if (r.output) lines.push(c.gray(String(r.output).split('\n').slice(-12).map((l) => '      ' + l).join('\n')));
    }
    if (d.notRun?.length) lines.push(`  ${sym.wait} ${c.yellow(`не запускалось: ${d.notRun.join(', ')}`)}`);
    return lines.join('\n');
}

const unwrap = (t: z.ZodTypeAny): z.ZodTypeAny => {
    while (t instanceof z.ZodDefault || t instanceof z.ZodOptional || t instanceof z.ZodNullable || t instanceof z.ZodEffects) t = t instanceof z.ZodEffects ? t._def.schema : t._def.innerType;
    return t;
};

const defaultOf = (t: z.ZodTypeAny) => (t instanceof z.ZodDefault ? (t._def.defaultValue as () => unknown)() : undefined);

function showValue(v: unknown): string {
    if (v === undefined) return '';
    if (typeof v === 'boolean') return v ? 'да' : 'нет';
    if (Array.isArray(v) && v.every((x) => typeof x !== 'object')) return v.join(', ');
    return typeof v === 'string' ? v : JSON.stringify(v);
}

/** What a target will hit, right in the card: «→ 4 хоста: nl-1 nl-2 …». */
function targetHint(d: Deps, v: unknown, strict: boolean): string | undefined {
    if (typeof v !== 'string' || !v) return undefined;
    try {
        const hosts = d.ctx.inventory().resolve(v);
        const names = hosts.map((h) => h.name);
        return `→ ${names.length} ${names.length === 1 ? 'хост' : names.length < 5 ? 'хоста' : 'хостов'}: ${names.slice(0, 8).join(' ')}${names.length > 8 ? ' …' : ''}`;
    } catch (e) {
        // «host» is sometimes a filter (journal): only a real target shows the error
        return strict ? c.red(`✖ ${(e as Error).message}`) : undefined;
    }
}

/**
 * Parameters as one card: required ones are asked first, then every field is shown with its value or
 * default; Enter on the first line goes on, Enter on a field edits just that field, Esc — back.
 */
async function paramsCard(shape: z.ZodRawShape, preset: Record<string, unknown>, d: Deps, o: { go: string; values?: Record<string, unknown>; path: string[] }): Promise<Record<string, unknown> | undefined> {
    const fields = Object.entries(shape).filter(([k]) => !['apply', 'planHash'].includes(k) && !(k in preset)) as Array<[string, z.ZodTypeAny]>;
    // a recent run may carry a parameter the tool no longer has
    const out: Record<string, unknown> = { ...preset, ...Object.fromEntries(Object.entries(o.values ?? {}).filter(([k]) => k in shape)) };
    for (const [k, t] of fields) if (!t.isOptional() && out[k] === undefined) out[k] = await askOne(k, t, d, true);
    if (!fields.length) return out;
    let cursor = 0;
    for (;;) {
        const w = Math.max(...fields.map(([k]) => k.length));
        const items: Choice[] = [
            { label: c.green(c.bold(o.go)), hint: '← Enter здесь — дальше' },
            ...fields.map(([k, t]) => {
                const v = out[k];
                const def = defaultOf(t);
                const shown = v !== undefined ? c.bold(showValue(HIDDEN.has(k) ? '•••' : v)) : def !== undefined ? `${showValue(def)} ${c.gray('(по умолчанию)')}` : c.gray('—');
                const about = PARAM_RU[k] ?? firstSentence(t.description ?? '', 70);
                const hint = (k === 'target' || k === 'host') && v !== undefined ? (targetHint(d, v, k === 'target') ?? about) : about;
                return { label: `${k.padEnd(w)}  ${shown}`, hint, keys: k };
            }),
        ];
        const i = await d.choose(crumb(...o.path), items, { initial: cursor, footer: 'Enter на «▶» — дальше · Enter на поле — поменять его · Esc — назад' });
        if (i === undefined) return undefined;
        if (i === 0) {
            const r = z.object(shape).strict().safeParse(out);
            if (r.success) return out;
            for (const issue of r.error.issues) console.log(`${sym.fail} ${c.red(`${String(issue.path[0] ?? '')}: ${issue.message}`)}`);
            cursor = Math.max(0, fields.findIndex(([k]) => k === String(r.error.issues[0].path[0])) + 1);
            continue;
        }
        const [k, t] = fields[i - 1];
        cursor = i;
        const base = unwrap(t);
        // a yes/no field just flips
        if (base instanceof z.ZodBoolean) out[k] = !(out[k] ?? defaultOf(t) ?? false);
        else {
            const v = await askOne(k, t, d, !t.isOptional(), out[k]);
            if (v === undefined && t.isOptional()) delete out[k];
            else if (v !== undefined) out[k] = v;
        }
    }
}

/** Plain text of a value for editing in place. */
function editable(v: unknown): string {
    if (v === undefined) return '';
    if (Array.isArray(v) && v.every((x) => typeof x !== 'object')) return v.join(',');
    return typeof v === 'string' ? v : JSON.stringify(v);
}

async function askOne(name: string, t: z.ZodTypeAny, d: Deps, required: boolean, current?: unknown): Promise<unknown> {
    const base = unwrap(t);
    const def = defaultOf(t);
    const hint = PARAM_RU[name] ?? firstSentence(t.description ?? '', 90);
    if (base instanceof z.ZodEnum) {
        const opts = base.options as string[];
        const at = opts.indexOf(String(current ?? def));
        for (;;) {
            const i = await d.choose(`${c.bold(name)}${hint ? c.gray(` — ${hint}`) : ''}`, opts.map((x) => ({ label: x, hint: x === def ? 'по умолчанию' : undefined })), { initial: Math.max(0, at) });
            if (i !== undefined) return opts[i];
            if (current !== undefined || def !== undefined || !required || t.isOptional()) return current;
            console.log(`    ${sym.warn} ${c.yellow('нужно выбрать значение')}`);
        }
    }
    const tail = def !== undefined ? c.gray(` [${showValue(def)}]`) : !required ? c.gray(' [Enter — пусто]') : '';
    for (;;) {
        const prompt = `  ${c.bold(name)}${hint ? c.gray(` — ${hint}`) : ''}${base instanceof z.ZodBoolean ? c.gray(' (да/нет)') : ''}${tail}: `;
        const raw = (HIDDEN.has(name) ? await d.askSecret(prompt) : await d.ask(prompt, { initial: editable(current) })).trim();
        if (!raw) {
            if (def !== undefined || !required || t.isOptional()) return undefined;
            console.log(`    ${sym.warn} ${c.yellow('нужно значение')}`);
            continue;
        }
        try {
            const v = convert(raw, base);
            const check = t.safeParse(v);
            if (!check.success) throw new Error(check.error.issues[0].message);
            return v;
        } catch (e) {
            console.log(`    ${sym.fail} ${c.red((e as Error).message)}`);
        }
    }
}

export function convert(raw: string, base: z.ZodTypeAny): unknown {
    if (base instanceof z.ZodEnum) {
        const opts = base.options as string[];
        const v = opts[Number(raw) - 1] ?? opts.find((o) => o === raw);
        if (!v) throw new Error(`одно из: ${opts.join(', ')}`);
        return v;
    }
    if (base instanceof z.ZodBoolean) {
        if (/^(да|д|y|yes|true|1|l)$/i.test(raw)) return true;
        if (/^(нет|н|n|no|false|0)$/i.test(raw)) return false;
        throw new Error('да или нет');
    }
    if (base instanceof z.ZodNumber) {
        const n = Number(raw);
        if (Number.isNaN(n)) throw new Error('нужно число');
        return n;
    }
    if (base instanceof z.ZodArray) {
        if (raw.startsWith('[')) return JSON.parse(raw);
        const items = raw.split(',').map((s) => s.trim()).filter(Boolean);
        return unwrap(base.element) instanceof z.ZodNumber ? items.map(Number) : items;
    }
    if (base instanceof z.ZodString) return raw;
    // unions (text or list), records, objects: JSON, or plain text / comma list
    if (/^[[{]/.test(raw)) return JSON.parse(raw);
    return raw;
}
