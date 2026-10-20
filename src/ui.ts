import readline from 'node:readline/promises';
import { stringify } from 'yaml';
import { z } from 'zod';
import { c, hlYaml, tone } from './color.js';
import { statusTable } from './status-view.js';
import { Advance, Decision, ScenarioEngine } from './core/scenario.js';
import { spin } from './tui.js';
import { registry } from './tools/helpers.js';

/** Everything the owner reads in the terminal is Russian; tool data (JSON for MCP) stays as it is. */

/** Is this schema field a string at heart (so "123" / "3e12" must stay strings, e.g. planHash)? */
export function wantsString(t: z.ZodTypeAny | undefined): boolean {
    while (t && (t instanceof z.ZodDefault || t instanceof z.ZodOptional || t instanceof z.ZodNullable)) t = t._def.innerType;
    return t instanceof z.ZodString || t instanceof z.ZodEnum;
}

export function parseArgs(rest: string[], shape: Record<string, unknown> = {}): Record<string, unknown> {
    if (rest.length === 1 && rest[0].trim().startsWith('{')) return JSON.parse(rest[0]);
    const out: Record<string, unknown> = {};
    for (const a of rest) {
        const i = a.indexOf('=');
        if (i <= 0) throw new Error(`аргумент «${a}» не в виде ключ=значение`);
        const k = a.slice(0, i);
        const v = a.slice(i + 1);
        if (wantsString(shape[k] as z.ZodTypeAny | undefined)) {
            out[k] = v;
            continue;
        }
        try {
            out[k] = JSON.parse(v);
        } catch {
            out[k] = v;
        }
    }
    return out;
}

export function firstSentence(s: string, max = 150): string {
    const m = s.match(/^.*?[.!?](?=\s+[A-ZА-Я(`]|$)/);
    const first = m ? m[0] : s;
    return first.length > max ? first.slice(0, max - 1) + '…' : first;
}

/** Column headers and values of the tool rows, in Russian. */
const HEAD: Record<string, string> = {
    host: 'хост',
    state: 'состояние',
    up: 'аптайм',
    load: 'нагрузка',
    cpu: 'ядер',
    mem: 'память',
    temp: 'темп.',
    disk: 'диск',
    updates: 'обновл.',
    reboot: 'ребут',
    node: 'remnanode',
    cert: 'серт.',
    ts: 'tailscale',
    tsKey: 'ключ ts',
    panel: 'панель',
    issues: 'проблемы',
    error: 'ошибка',
    device: 'устройство',
    online: 'в сети',
    ip: 'ip',
    os: 'ОС',
    update: 'обновление',
    key: 'ключ',
    tags: 'теги',
    self: 'эта машина',
    run: 'прогон',
    scenario: 'ранбук',
    step: 'шаг',
    finished: 'завершён',
    updatedAt: 'изменён',
    check: 'проверка',
    result: 'результат',
    group: 'группа',
    name: 'имя',
    about: 'что это',
};
const VALUE: Record<string, string> = {
    UNREACHABLE: 'НЕДОСТУПЕН',
    'not in fleet.yaml': 'нет в fleet.yaml',
    offline: 'не в сети',
    crit: 'КРИТ',
    warn: 'внимание',
    ok: 'ok',
    info: 'ok',
    yes: 'да',
    available: 'есть',
    EXPIRED: 'ИСТЁК',
    true: 'да',
    false: 'нет',
};
const ru = (v: unknown) => {
    if (v === undefined || v === null) return '';
    const s = v === true ? 'да' : String(v);
    return VALUE[s] ?? s.replace(/^no, /, 'нет, ').replace(/^online/, 'в сети').replace(/^offline/, 'не в сети');
};

/** Columns whose words carry a state worth colouring. */
const TONED = new Set(['state', 'node', 'panel', 'online', 'ts', 'tsKey', 'key', 'result', 'issues', 'error', 'update', 'finished', 'reboot']);

export function table(rows: Array<Record<string, unknown>>): string {
    const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))].filter((k) => rows.some((r) => r[k] !== undefined && r[k] !== ''));
    const width = cols.map((k) => Math.min(60, Math.max((HEAD[k] ?? k).length, ...rows.map((r) => ru(r[k]).length))));
    // cut and pad first, colour after: escape codes must not count towards the width
    const last = cols.length - 1;
    const cell = (k: string, v: string, i: number) => {
        const cut = v.length > width[i] ? `${v.slice(0, width[i] - 1)}…` : v;
        const padded = i === last ? cut : cut.padEnd(width[i]);
        if (k === 'issues' || k === 'error') return v ? c.red(padded) : padded;
        if (k === 'host' || k === 'device') return c.bold(padded);
        return TONED.has(k) ? tone(padded) : padded;
    };
    const bar = ` ${c.gray('│')} `;
    const head = cols.map((k, i) => c.bold(i === last ? (HEAD[k] ?? k) : (HEAD[k] ?? k).padEnd(width[i]))).join(bar);
    return [head, c.gray(width.map((w) => '─'.repeat(w)).join('─┼─')), ...rows.map((r) => cols.map((k, i) => cell(k, ru(r[k]), i)).join(bar).trimEnd())].join('\n');
}

export function clip(text: string, lines: number): string {
    const all = text.trimEnd().split('\n');
    return all.length > lines ? [...all.slice(0, lines), c.gray(`… ещё ${all.length - lines} строк (полностью: --json)`)].join('\n') : all.join('\n');
}

/** YAML of any value, highlighted and clipped. */
export const yamlOut = (v: unknown, lines = 200) => hlYaml(clip(stringify(v, { lineWidth: 0 }), lines));

/** Service lines of tool results (panel / tailnet state) in Russian. */
export function ruLine(s: string): string {
    return s
        .replace(/^not configured \(([^)]*)\)/, 'не задана ($1)')
        .replace(/^not configured/, 'не задана')
        .replace(/^ok, (\d+) nodes/, 'ok, $1 нод')
        .replace(/^error: /, 'ошибка: ')
        .replace(/^unavailable: /, 'недоступен: ')
        .replace(/^(\d+) devices, (\d+) online/, '$1 устройств, $2 в сети');
}

const SUMMARY: Record<string, string> = { hosts: 'хостов', ok: 'ok', warn: 'внимание', crit: 'крит.', unreachable: 'недоступны', tailnetOnly: 'только в tailnet' };

export async function callTool(name: string, args: Record<string, unknown>): Promise<{ text: string; isError?: boolean; data: unknown }> {
    const t = registry.get(name);
    if (!t) throw new Error(`нет инструмента ${name}; список: mia tools`);
    const check = z.object(t.schema as z.ZodRawShape).strict().safeParse(args);
    if (!check.success) throw new Error(`${name}: ${check.error.issues.map((i) => `${i.path.join('.') || 'аргументы'}: ${i.message}`).join('; ')}`);
    const res = await t.handler(check.data);
    const text = res.content.map((c) => c.text).join('\n');
    let data: unknown = text;
    try {
        data = JSON.parse(text);
    } catch {
        /* text */
    }
    return { text, isError: res.isError, data };
}

/** A tool result for a human: status and row lists as tables, the rest as YAML. */
export function showResult(tool: string, data: unknown, maxLines = 200): string {
    if (typeof data === 'string') return data;
    const d = data as Record<string, any>;
    if (tool === 'fleet_status' && Array.isArray(d?.rows)) {
        return statusTable({ rows: d.rows, summary: d.summary, hint: d.hint, panel: d.panel ? ruLine(String(d.panel)) : undefined, tailnet: d.tailnet ? ruLine(String(d.tailnet)) : undefined });
    }
    if (Array.isArray(d?.rows) && d.rows.length && typeof d.rows[0] === 'object') {
        const colourSum = (k: string, v: unknown) => {
            const t = `${SUMMARY[k] ?? k}: ${v}`;
            if (!v) return c.gray(t);
            return k === 'crit' || k === 'unreachable' ? c.red(t) : k === 'warn' || k === 'tailnetOnly' ? c.yellow(t) : k === 'ok' ? c.green(t) : c.bold(t);
        };
        const head = tool === 'fleet_status' && d.summary ? `${Object.entries(d.summary).map(([k, v]) => colourSum(k, v)).join('  ')}   ${c.gray('панель:')} ${tone(ruLine(String(d.panel)))}${d.tailnet ? `   ${c.gray('tailnet:')} ${tone(ruLine(String(d.tailnet)))}` : ''}` : '';
        const rest = Object.fromEntries(Object.entries(d).filter(([k]) => !['rows', 'summary', 'panel', 'tailnet', 'hint'].includes(k)));
        return [table(d.rows), head && `\n${head}`, Object.keys(rest).length && tool !== 'fleet_status' ? `\n${yamlOut(rest, 40)}` : '', d.hint ? `\n${c.gray('подсказка:')} ${d.hint}` : '']
            .filter(Boolean)
            .join('\n');
    }
    if (tool === 'fleet_audit' && d?.findings) {
        const lines: string[] = [];
        for (const [h, list] of Object.entries(d.findings as Record<string, string[]>)) {
            lines.push(c.bold(`${h}:`));
            for (const x of list) {
                const [sev, ...restWords] = x.split(' ');
                const code = restWords.join(' ').replace(/^([\w.]+):/, (_m, k: string) => c.cyan(k) + ':');
                lines.push(`  ${sev === 'CRIT' ? c.red('КРИТ') : sev === 'WARN' ? c.yellow('ВНИМ') : c.gray('инфо')} ${code}`);
            }
        }
        if (d.clean) lines.push(`\n${c.green('без замечаний:')} ${[].concat(d.clean).join(', ')}`);
        lines.push(`\n${c.gray('панель:')} ${tone(ruLine(String(d.panel)))}`);
        return lines.join('\n') || c.green('замечаний нет');
    }
    return yamlOut(data, maxLines);
}

// ------------------------------------------------------------------ runbook walk

/** Answers in either keyboard layout: s/ы, d/в, r/к, q/й, and the Russian words. */
const ANSWERS: Record<string, Decision | 'quit'> = {
    s: 'skip',
    ы: 'skip',
    skip: 'skip',
    пропустить: 'skip',
    d: 'done',
    в: 'done',
    done: 'done',
    сделано: 'done',
    готово: 'done',
    r: 'retry',
    к: 'retry',
    retry: 'retry',
    повторить: 'retry',
    q: 'quit',
    й: 'quit',
    quit: 'quit',
    выход: 'quit',
};
/** A change runs only on the whole word (or «да»): a stray key must never touch prod. */
const APPLY = new Set(['apply', 'да', 'фззднж']);

// «н» and «y» share a key: «н» is no (the prompt says so), a lone «y» is asked again instead of guessed
const YES = new Set(['', 'да', 'д', 'lf', 'l', 'yes', 'apply', 'фззднж', 'ок', 'ok']);
const NO = new Set(['н', 'нет', 'n', 'no', 'тщ', 'ytn', 'отмена', 'q', 'й']);

/** What an irreversible plan asks to be typed back instead of Enter. */
export interface Risk {
    text: string;
    answer: string;
}

export const plural = (n: number, one: string, few: string, many: string) => (n % 10 === 1 && n % 100 !== 11 ? one : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? few : many);

/**
 * Reboots, deleted DNS records and machines removed from the tailnet cannot be taken back: for them
 * Enter is not enough — the host count (or the one name) is typed, as clig.dev / terraform do.
 */
export function riskOf(tool: string | undefined, data: unknown): Risk | undefined {
    const plan = ((data as { plan?: Array<Record<string, unknown>> })?.plan ?? []).filter((p) => !p.skip && !(p.blockers as unknown[] | undefined)?.length);
    const who = (p: Record<string, unknown>) => String(p.host ?? p.target ?? '');
    const ask = (names: string[], what: (n: number) => string): Risk | undefined =>
        !names.length ? undefined : names.length === 1 ? { text: `${what(1)}: ${names[0]}`, answer: names[0] } : { text: `${what(names.length)}: ${names.slice(0, 8).join(', ')}${names.length > 8 ? ' …' : ''}`, answer: String(names.length) };
    if (tool === 'host_reboot') return ask(plan.map(who), (n) => `Перезагрузить ${n === 1 ? 'сервер' : `${n} ${plural(n, 'сервер', 'сервера', 'серверов')}`}`);
    if (tool === 'tailnet_device_remove') return ask(plan.map((p) => who(p).replace(/^tailnet /, '').split('.')[0]), (n) => `Удалить из tailnet ${n === 1 ? 'машину' : `${n} машин`}`);
    if (tool === 'dns_change') {
        const del = plan.filter((p) => /^delete\b/.test(String(p.will ?? '')));
        return ask(del.map((p) => who(p).replace(/^\w+ /, '')), (n) => `Удалить ${n === 1 ? 'DNS-запись' : `${n} ${plural(n, 'DNS-запись', 'DNS-записи', 'DNS-записей')}`}`);
    }
    return undefined;
}

/** Irreversible: type the answer; Enter or anything else cancels. */
export async function typedConfirm(ask: Ask, r: Risk): Promise<boolean> {
    console.log(`${c.yellow('▲')} ${c.bold(r.text)}. ${c.yellow('Это не отменить.')}`);
    const a = (await ask(`  Для подтверждения введите ${c.bold(r.answer)} ${c.gray('(Enter — отмена)')}: `)).trim();
    if (a.toLowerCase() === r.answer.toLowerCase()) return true;
    console.log(c.gray(a ? `  «${a}» ≠ «${r.answer}» — ничего не сделано.` : '  Отменено, ничего не сделано.'));
    return false;
}

/** «п» — the parameters (in either layout). */
export const PARAMS = new Set(['п', 'g', 'p', 'з', 'параметры', 'params']);

/**
 * The one question before a plan runs: Enter — yes, «н» — no, «п» — change the parameters.
 * An irreversible plan wants its count or name typed instead of Enter.
 */
export async function decidePlan(ask: Ask, risk?: Risk): Promise<'yes' | 'no' | 'params'> {
    if (risk) console.log(`${c.yellow('▲')} ${c.bold(risk.text)}. ${c.yellow('Это не отменить.')}`);
    for (;;) {
        const q = risk ? `  Для подтверждения введите ${c.bold(risk.answer)} ${c.gray('(Enter — отмена · п — параметры)')}: ` : `${c.bold('Выполнить этот план?')} ${c.gray('[Enter — да · н — нет · п — параметры]')} `;
        const a = (await ask(q)).trim().toLowerCase();
        if (PARAMS.has(a)) return 'params';
        if (risk) {
            if (a === risk.answer.toLowerCase()) return 'yes';
            console.log(c.gray(a ? `  «${a}» ≠ «${risk.answer}» — ничего не сделано.` : '  Отменено, ничего не сделано.'));
            return 'no';
        }
        if (YES.has(a)) return 'yes';
        if (NO.has(a)) {
            console.log(c.gray('Отменено, ничего не сделано.'));
            return 'no';
        }
        console.log(c.yellow('Enter — да, «н» — нет, «п» — параметры'));
    }
}

/** Yes/no with Enter meaning yes (the owner's choice). Returns false on no, asks again on anything unclear. */
export async function confirm(ask: Ask, question: string): Promise<boolean> {
    for (;;) {
        const a = (await ask(`${question} ${c.gray('[Enter — да · н — нет]')} `)).trim().toLowerCase();
        if (YES.has(a)) return true;
        if (NO.has(a)) return false;
        console.log(c.yellow('Enter — да, «н» или «нет» — нет'));
    }
}

const CHOICE: Record<Decision, string> = { apply: 'да — выполнить', done: 'd — сделано', skip: 's — пропустить', retry: 'r — проверить снова' };

/** What Enter answers on a step: run it, mark the manual work done, or check again. */
const defaultChoice = (choices: Decision[]): Decision | undefined => (['apply', 'done', 'retry'] as Decision[]).find((x) => choices.includes(x));
const STATUS: Record<string, string> = { passed: 'пройдено', 'n/a': 'не нужно', applied: 'выполнено', done: 'сделано', skipped: 'пропущено', failed: 'ОШИБКА', replanned: 'план изменился — показан новый' };
const KIND: Record<string, string> = { check: 'проверка', mia: 'изменение на серверах', panel: 'изменение в панели', manual: 'руками', inventory: 'fleet.yaml', local: 'репозиторий на этой машине' };

export type Ask = (q: string) => Promise<string>;

/** Walk a runbook: print what passed, show the waiting step, ask, repeat. Without `ask` and a TTY: print how to continue. */
export async function walk(engine: ScenarioEngine, adv: Advance, ask?: Ask) {
    let own: readline.Interface | undefined;
    if (!ask && process.stdin.isTTY) {
        own = readline.createInterface({ input: process.stdin, output: process.stdout });
        ask = (q) => own!.question(q);
    }
    try {
        for (;;) {
            if (adv.outcome) {
                const o = adv.outcome;
                const text = `${o.id}: ${STATUS[o.status] ?? o.status}${o.summary && o.summary !== o.status ? ` — ${o.summary}` : ''}`;
                console.log(o.status === 'failed' ? `${c.red('✖')} ${c.red(text)}` : o.status === 'skipped' ? `${c.yellow('▲')} ${c.yellow(text)}` : `${c.green('✔')} ${text}`);
            }
            // a run of automatic checks is one line; details stay in «mia scenario show»
            if (adv.passed.length > 3) {
                const okN = adv.passed.filter((p) => p.status === 'passed').length;
                console.log(`${c.green('✔')} ${okN} ${okN === 1 ? 'проверка пройдена' : 'проверок пройдено'}${adv.passed.length > okN ? c.gray(`, ${adv.passed.length - okN} не нужны`) : ''}: ${c.gray(adv.passed.map((p) => p.title.replace(/\s*\(.*$/, '')).join(' · ').slice(0, 220))}`);
            } else for (const p of adv.passed) console.log(`${p.status === 'passed' ? c.green('✔') : c.gray('·')} ${p.title}${p.status !== 'passed' ? c.gray(` (${STATUS[p.status] ?? p.status})`) : ''}${p.summary ? c.gray(` — ${p.summary.slice(0, 160)}`) : ''}`);
            if (adv.outcome?.status === 'failed' && adv.outcome.result !== undefined) console.log(yamlOut(adv.outcome.result, 40));
            if (adv.finished || !adv.step) {
                console.log(`\n${c.green('✔')} ${c.green(c.bold('Ранбук пройден.'))}`);
                for (const l of adv.log ?? []) console.log(`  ${tone((STATUS[l.status] ?? l.status).padEnd(10))} ${l.id}${l.summary ? c.gray(` — ${l.summary.slice(0, 120)}`) : ''}`);
                return;
            }
            const s = adv.step;
            const filled = Math.round((12 * (s.n - 1)) / Math.max(1, s.total));
            console.log(`\n${c.cyan('◆')} ${c.gray(`шаг ${s.n}/${s.total}`)} ${c.cyan('█'.repeat(filled))}${c.gray('░'.repeat(12 - filled))}  ${c.bold(s.title)}  ${c.gray(`(${KIND[s.kind] ?? s.kind})`)}`);
            if (s.preview !== undefined) console.log(typeof s.preview === 'string' ? s.preview : yamlOut(s.preview, 70));
            if (s.problem) console.log(`${c.red('✖')} ${c.red(s.problem)}`);
            // an irreversible step is never Enter away
            const def = riskOf(s.tool, s.preview) ? undefined : defaultChoice(s.choices);
            const hint = [
                ...(def ? [c.bold(c.green(`Enter — ${CHOICE[def].replace(/^.*? — /, '')}`))] : []),
                ...s.choices.filter((x) => x !== def).map((x) => CHOICE[x]),
                c.gray('set ключ=значение — поменять параметр'),
                c.gray('q — выйти (прогресс сохранится)'),
            ].join('   ');
            if (!ask) {
                console.log(`\n${c.yellow('Ждёт ответа:')} mia scenario step ${s.run} <${s.choices.join('|')}>   или   mia scenario resume ${s.run}`);
                return;
            }
            let decision: Decision | undefined;
            while (!decision) {
                const raw = (await ask(`${hint}\n> `)).trim();
                const a = raw.toLowerCase();
                // «set ключ=значение …» / «задать …»: поменять параметры прогона на ходу и перепроверить шаг
                const setm = raw.match(/^(?:set|задать)\s+(.+)$/i);
                if (setm) {
                    try {
                        const def = engine.list().find((x) => x.name === s.scenario);
                        const shape = Object.fromEntries((def?.params ?? []).map((p) => [p.name, undefined]));
                        adv = await spin('перепроверяю шаг', () => engine.setParams(s.run, parseArgs(setm[1].split(/\s+(?=\w+=)/), shape)));
                        console.log(c.green('Параметры обновлены.'));
                    } catch (e) {
                        console.log(c.red(`Не вышло: ${(e as Error).message}`));
                        continue;
                    }
                    break;
                }
                const mapped = a === '' ? def : APPLY.has(a) ? 'apply' : ANSWERS[a];
                if (mapped === 'quit') {
                    console.log(`Сохранено. Продолжить: ${c.bold(`mia scenario resume ${s.run}`)}`);
                    return;
                }
                if (mapped === 'apply' && s.choices.includes('apply')) {
                    const risk = riskOf(s.tool, s.preview);
                    if (risk && !(await typedConfirm(ask, risk))) continue;
                }
                if (mapped && s.choices.includes(mapped)) decision = mapped;
                else if (!a) console.log(c.yellow('Здесь Enter ничего не выбирает. Варианты: ') + hint);
                else console.log(c.yellow('Не понял. Варианты: ') + hint);
            }
            if (decision) {
                const d = decision;
                adv = await spin(d === 'apply' ? 'выполняю шаг' : d === 'retry' ? 'проверяю снова' : 'дальше', () => engine.decide(s.run, d));
            }
        }
    } finally {
        own?.close();
    }
}
