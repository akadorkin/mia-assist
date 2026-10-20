import fs from 'node:fs';
import path from 'node:path';
import { c, clipVisible } from './color.js';
import { Progress, withProgress } from './core/progress.js';
import { shq } from './core/ssh.js';

/**
 * One visual language for the console: the same symbols everywhere (colour only backs them up),
 * where-am-I crumbs, a timer while mia waits on ssh or an API, the one-line command of every
 * interactive run, and the recent actions the main menu offers again.
 */
export const sym = {
    ok: c.green('✔'),
    fail: c.red('✖'),
    warn: c.yellow('▲'),
    live: c.green('●'),
    wait: c.gray('○'),
    skip: c.gray('·'),
    step: c.cyan('◆'),
    done: c.gray('◇'),
    bar: c.gray('│'),
    end: c.gray('└'),
};

export const crumb = (...parts: string[]) => ['mia', ...parts].join(c.gray(' › '));

const FRAMES = ['◐', '◓', '◑', '◒'];
const clock = (ms: number) => {
    const s = Math.floor(ms / 1000);
    return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
};

interface HostState {
    state: 'wait' | 'run' | 'ok' | 'fail';
    since: number;
    ms?: number;
    note?: string;
}

/** Hosts of the current phase and how each is doing; built from progress events. */
export class LiveHosts {
    hosts = new Map<string, HostState>();
    phase?: string;

    on(e: Progress, now = Date.now()) {
        if (e.kind === 'hosts') {
            // a new phase (probe → apply) starts a fresh list
            if (e.phase !== this.phase) this.hosts.clear();
            this.phase = e.phase;
            for (const h of e.hosts) if (!this.hosts.has(h)) this.hosts.set(h, { state: 'wait', since: now });
            return;
        }
        const cur = this.hosts.get(e.host);
        if (e.state === 'run') {
            // several commands per host: it stays «running» until the last one ends
            this.hosts.set(e.host, { state: 'run', since: cur?.state === 'run' ? cur.since : now });
        } else this.hosts.set(e.host, { state: e.state, since: cur?.since ?? now, ms: e.ms, note: e.note });
    }

    counts() {
        const all = [...this.hosts.values()];
        return { total: all.length, done: all.filter((h) => h.state === 'ok' || h.state === 'fail').length, failed: all.filter((h) => h.state === 'fail').length };
    }

    /** Lines under the spinner: one per host while they fit, else who runs now and what failed. */
    lines(width: number, room: number, now = Date.now()): string[] {
        const list = [...this.hosts.entries()];
        if (!list.length) return [];
        const w = Math.min(18, Math.max(...list.map(([n]) => n.length)));
        const mark = (h: HostState, frame: string) => (h.state === 'ok' ? sym.ok : h.state === 'fail' ? sym.fail : h.state === 'run' ? c.cyan(frame) : sym.wait);
        const frame = FRAMES[Math.floor(now / 120) % FRAMES.length];
        if (list.length <= Math.max(3, Math.min(10, room))) {
            return list.map(([n, h]) => {
                const t = h.state === 'run' ? c.gray(clock(now - h.since)) : h.ms !== undefined ? c.gray(`${(h.ms / 1000).toFixed(1)}s`) : '';
                return clipVisible(`  ${mark(h, frame)} ${n.padEnd(w)}  ${t}${h.state === 'fail' && h.note ? `  ${c.red(h.note.split(' — ')[0])}` : ''}`, width);
            });
        }
        const running = list.filter(([, h]) => h.state === 'run').map(([n]) => n);
        const failed = list.filter(([, h]) => h.state === 'fail');
        const out = running.length ? [clipVisible(`  ${c.cyan(frame)} сейчас: ${running.join(', ')}`, width)] : [];
        for (const [n, h] of failed.slice(-3)) out.push(clipVisible(`  ${sym.fail} ${n}  ${c.red((h.note ?? 'ошибка').split(' — ')[0])}`, width));
        if (failed.length > 3) out.push(c.gray(`    … ещё ${failed.length - 3} с ошибкой`));
        return out;
    }
}

/**
 * Run work with a live block on a terminal: spinner, elapsed time, «X из Y» and the hosts (from the
 * progress of the call); the block is cleared at the end and one grey line stays. Plain line otherwise.
 */
export async function spin<T>(label: string, work: () => Promise<T>, done?: (v: T) => string): Promise<T> {
    const started = Date.now();
    const tty = !!process.stdout.isTTY;
    const live = new LiveHosts();
    let drawn = 0;
    const draw = () => {
        const now = Date.now();
        const { total, done: n, failed } = live.counts();
        const head = `${c.cyan(FRAMES[Math.floor(now / 120) % FRAMES.length])} ${label}${total ? c.gray(` · ${n} из ${total}`) : ''}${failed ? ` ${sym.fail} ${c.red(String(failed))}` : ''} ${c.gray(clock(now - started))}`;
        const width = Math.max(20, (process.stdout.columns || 100) - 1);
        const lines = [clipVisible(head, width), ...live.lines(width, (process.stdout.rows || 30) - 6, now)];
        process.stdout.write(`\r${drawn > 1 ? `\x1b[${drawn - 1}A` : ''}\x1b[J${lines.join('\n')}`);
        drawn = lines.length;
    };
    const clear = () => process.stdout.write(`\r${drawn > 1 ? `\x1b[${drawn - 1}A` : ''}\x1b[J`);
    let timer: NodeJS.Timeout | undefined;
    // Ctrl+C outside the console (mia status): give the cursor back before leaving
    const onSig = () => {
        clearInterval(timer);
        process.stdout.write('\x1b[?25h\n');
        process.exit(130);
    };
    if (tty) {
        process.stdout.write('\x1b[?25l');
        process.once('SIGINT', onSig);
        draw();
        timer = setInterval(draw, 120);
    } else console.log(c.gray(`… ${label}`));
    const end = (mark: string, text: string) => {
        if (!tty) return;
        process.off('SIGINT', onSig);
        clearInterval(timer);
        clear();
        const { total, failed } = live.counts();
        const hosts = total ? c.gray(` · ${total} ${total === 1 ? 'хост' : total < 5 ? 'хоста' : 'хостов'}${failed ? `, ${failed} с ошибкой` : ''}`) : '';
        process.stdout.write(`\x1b[?25h${mark} ${text}${hosts} ${c.gray(`${((Date.now() - started) / 1000).toFixed(1)}s`)}\n`);
    };
    try {
        // the work starts inside the progress scope, so its ssh calls report here
        const v = await withProgress((e) => live.on(e), work);
        end(sym.done, c.gray(done ? done(v) : label));
        return v;
    } catch (e) {
        end(sym.fail, label);
        throw e;
    }
}


/** `mia call tool k=v …` for what was just run interactively (secrets never included). */
export function cmdLine(tool: string, args: Record<string, unknown>, hidden: Set<string> = new Set()): string {
    const parts = Object.entries(args)
        .filter(([k, v]) => v !== undefined && !['apply', 'planHash'].includes(k))
        .map(([k, v]) => `${k}=${hidden.has(k) ? '…' : shq(typeof v === 'string' ? v : Array.isArray(v) && v.every((x) => typeof x === 'string') ? v.join(',') : JSON.stringify(v))}`);
    return ['mia call', tool, ...parts].join(' ');
}

export interface Recent {
    tool: string;
    args: Record<string, unknown>;
    at: string;
}

const historyFile = (stateDir: string) => path.join(stateDir, 'console-recent.json');

export function recent(stateDir: string): Recent[] {
    try {
        return JSON.parse(fs.readFileSync(historyFile(stateDir), 'utf8')) as Recent[];
    } catch {
        return [];
    }
}

/** Remember a run for «Недавние» (newest first, no duplicates, no secret arguments). */
export function remember(stateDir: string, tool: string, args: Record<string, unknown>, hidden: Set<string> = new Set()) {
    if (Object.keys(args).some((k) => hidden.has(k) && args[k] !== undefined)) return;
    const clean = Object.fromEntries(Object.entries(args).filter(([k, v]) => v !== undefined && !['apply', 'planHash'].includes(k)));
    const key = JSON.stringify([tool, clean]);
    const list = [{ tool, args: clean, at: new Date().toISOString() }, ...recent(stateDir).filter((r) => JSON.stringify([r.tool, r.args]) !== key)].slice(0, 20);
    try {
        fs.mkdirSync(stateDir, { recursive: true });
        fs.writeFileSync(historyFile(stateDir), JSON.stringify(list, null, 1));
    } catch {
        /* a read-only state dir only loses the history */
    }
}

export function ago(iso: string): string {
    const m = Math.round((Date.now() - Date.parse(iso)) / 60_000);
    if (m < 1) return 'только что';
    if (m < 60) return `${m} мин назад`;
    if (m < 48 * 60) return `${Math.round(m / 60)} ч назад`;
    return `${Math.round(m / 1440)} дн назад`;
}

/** Short text of arguments for a menu line: target=all · lines=200. */
export const argsLine = (args: Record<string, unknown>) =>
    Object.entries(args)
        .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
        .join(' · ');
