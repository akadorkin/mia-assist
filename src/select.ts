import readline from 'node:readline';
import { c, clipVisible, strip } from './color.js';

/** Ctrl+C in a question or a menu: back to the main menu (or out of mia from there). */
export class Cancelled extends Error {}

export interface Choice {
    label: string;
    /** grey text after the label; searched too */
    hint?: string;
    /** extra words to find the item by (tool name, host …) */
    keys?: string;
}

export interface PickOpts {
    /** where the cursor starts */
    initial?: number;
    /** grey line under the list */
    footer?: string;
    /** several at once: Space ticks, Enter takes the ticked ones */
    multi?: boolean;
    /** ticked from the start (multi) */
    checked?: number[];
    /** found only by typing (indexes continue after items): every tool from the main menu */
    searchOnly?: Choice[];
    /** items before this index get no digit (recent runs above the sections keep 1 = the first section) */
    numberFrom?: number;
    /** multi: Enter with nothing ticked takes the highlighted item (one host is one Enter) */
    enterPicksCurrent?: boolean;
    /** what typed text can be taken as, when it is not just a search («использовать как цель») */
    freeText?: string;
    /** the search starts filled in (mia логи) */
    filter?: string;
    /** false: leave no «title › choice» line behind (menus: the next screen says where we are) */
    echo?: boolean;
}

export type PickResult = { kind: 'select'; index: number; alt?: boolean } | { kind: 'many'; indexes: number[] } | { kind: 'text'; text: string } | { kind: 'back' } | { kind: 'cancel' };

interface Key {
    name?: string;
    ctrl?: boolean;
    meta?: boolean;
    shift?: boolean;
}

const EN = "qwertyuiop[]asdfghjkl;'zxcvbnm,.`";
const RU = 'йцукенгшщзхъфывапролджэячсмитьбюё';
const swap = (s: string, from: string, to: string) => [...s].map((ch) => (from.includes(ch) ? to[from.indexOf(ch)] : ch)).join('');

/** The list state behind a menu: cursor, search filter, scrolling. Pure, so it is tested without a terminal. */
export class Picker {
    filter = '';
    cursor = 0;
    top = 0;
    readonly checked: Set<number>;

    constructor(
        readonly title: string,
        readonly items: Choice[],
        readonly opts: PickOpts = {},
    ) {
        this.cursor = Math.max(0, Math.min(items.length - 1, opts.initial ?? 0));
        this.checked = new Set(opts.checked ?? []);
        this.filter = opts.filter ?? '';
    }

    /** the typed text as a value: the last line of the list while searching */
    private get textIndex(): number | undefined {
        return this.opts.freeText && this.filter.trim() ? this.all.length : undefined;
    }

    /** Indexes (into items) that match the filter; the search works in either keyboard layout. */
    visible(): number[] {
        const f = this.filter.toLowerCase();
        if (!f) return this.items.map((_, i) => i);
        const alts = [f, swap(f, EN, RU), swap(f, RU, EN)];
        const hits = this.all.flatMap((it, i) => {
            const text = strip(`${it.label} ${it.hint ?? ''} ${it.keys ?? ''}`).toLowerCase();
            return alts.some((a) => text.includes(a)) ? [i] : [];
        });
        return this.textIndex !== undefined ? [...hits, this.textIndex] : hits;
    }

    /** items, then the search-only ones */
    get all(): Choice[] {
        return [...this.items, ...(this.opts.searchOnly ?? [])];
    }

    /** Short menus keep their numbers: 1–9, and 0 for a tenth item. */
    private get quickDigits() {
        return !this.filter && this.items.length - (this.opts.numberFrom ?? 0) <= 10 && !this.opts.multi;
    }

    key(str: string | undefined, key: Key = {}): PickResult | undefined {
        const list = this.visible();
        const n = list.length;
        const move = (d: number) => {
            if (n) this.cursor = (((this.cursor + d) % n) + n) % n;
        };
        if (key.ctrl && (key.name === 'c' || key.name === 'd')) return { kind: 'cancel' };
        switch (key.name) {
            case 'up':
                return void move(-1);
            case 'down':
                return void move(1);
            case 'tab':
                return void move(key.shift ? -1 : 1);
            case 'pageup':
                return void (this.cursor = Math.max(0, this.cursor - 10));
            case 'pagedown':
                return void (this.cursor = Math.max(0, Math.min(n - 1, this.cursor + 10)));
            case 'home':
                return void (this.cursor = 0);
            case 'end':
                return void (this.cursor = Math.max(0, n - 1));
            case 'return':
            case 'enter': {
                const at = n ? list[Math.min(this.cursor, n - 1)] : undefined;
                if (at !== undefined && at === this.textIndex) return { kind: 'text', text: this.filter.trim() };
                if (this.opts.multi) {
                    if (!this.checked.size && this.opts.enterPicksCurrent && at !== undefined) return { kind: 'many', indexes: [at] };
                    return { kind: 'many', indexes: [...this.checked].sort((a, b) => a - b) };
                }
                return at !== undefined ? { kind: 'select', index: at } : undefined;
            }
            case 'right': {
                const at = n ? list[Math.min(this.cursor, n - 1)] : undefined;
                if (this.opts.multi || at === undefined || at === this.textIndex) return undefined;
                return { kind: 'select', index: at, alt: true };
            }
            case 'space':
                if (!this.opts.multi || !n) break;
                {
                    const i = list[Math.min(this.cursor, n - 1)];
                    if (i === this.textIndex) return undefined;
                    if (this.checked.has(i)) this.checked.delete(i);
                    else this.checked.add(i);
                }
                return undefined;
            case 'escape':
                if (this.filter) return void this.setFilter('');
                return { kind: 'back' };
            case 'left':
                return { kind: 'back' };
            case 'backspace':
                return void this.setFilter(this.filter.slice(0, -1));
        }
        if (!str || key.ctrl || key.meta || str.length !== 1 || str < ' ') return undefined;
        if (this.quickDigits && /[0-9]/.test(str)) {
            const i = (str === '0' ? 9 : Number(str) - 1) + (this.opts.numberFrom ?? 0);
            return i < this.items.length ? { kind: 'select', index: i } : undefined;
        }
        if (!this.filter && (str === 'q' || str === 'й')) return { kind: 'back' };
        this.setFilter(this.filter + str);
        return undefined;
    }

    private setFilter(f: string) {
        this.filter = f;
        this.cursor = 0;
        this.top = 0;
    }

    /** Lines to draw, each cut to the terminal width (a wrapped line would break redrawing in place). */
    render(cols = 100, rows = 30): string[] {
        const list = this.visible();
        const room = Math.max(3, rows - 6);
        if (this.cursor < this.top) this.top = this.cursor;
        if (this.cursor >= this.top + room) this.top = this.cursor - room + 1;
        this.top = Math.max(0, Math.min(this.top, Math.max(0, list.length - room)));
        const shown = list.slice(this.top, this.top + room);
        const help = this.opts.multi
            ? c.gray(this.opts.enterPicksCurrent ? '↑↓ Enter — выбрать · Пробел — отметить несколько · Esc — назад · буквы — поиск' : '↑↓ · Пробел — отметить · Enter — готово · Esc — назад · буквы — поиск')
            : this.items.length > 1
              ? c.gray(`↑↓ Enter${this.quickDigits ? ' или цифра' : ''} · Esc — назад · буквы — поиск`)
              : '';
        const out = [`${c.bold(this.title)}  ${help}`];
        if (this.top > 0) out.push(c.gray(`    ↑ ещё ${this.top}`));
        const found = list.filter((i) => i !== this.textIndex).length;
        for (const [k, i] of shown.entries()) {
            if (i === this.textIndex) {
                const on = this.top + k === this.cursor;
                out.push(`${on ? c.cyan('❯ ') : '  '}${c.yellow('✎')} ${on ? c.bold(this.opts.freeText!) : this.opts.freeText}: ${c.bold(this.filter.trim())}`);
                continue;
            }
            const it = this.all[i];
            const on = this.top + k === this.cursor;
            const from = this.opts.numberFrom ?? 0;
            const num = this.opts.multi ? (this.checked.has(i) ? c.green('◉ ') : c.gray('◯ ')) : this.quickDigits ? (i >= from ? c.gray(`${(i - from + 1) % 10} `) : '  ') : '';
            const label = on ? c.bold(c.cyan(strip(it.label))) : it.label;
            out.push(`${on ? c.cyan('❯ ') : '  '}${num}${label}${it.hint ? `  ${c.gray(strip(it.hint))}` : ''}`);
        }
        const below = list.length - this.top - shown.length;
        if (below > 0) out.push(c.gray(`    ↓ ещё ${below}`));
        if (!found) out.push(c.gray(this.textIndex !== undefined ? '    в списке нет — Enter возьмёт набранное' : '    ничего не найдено'));
        if (this.filter) out.push(`  ${c.yellow('поиск:')} ${this.filter}${c.gray(`  (${found} из ${this.all.length}; Esc — сбросить)`)}`);
        if (this.opts.footer) out.push(c.gray(`  ${this.opts.footer}`));
        return out.map((l) => clipVisible(l, Math.max(20, cols - 2)));
    }
}

/** Arrow menus need a real terminal; MIA_NUMBERS=1 keeps the numbered lists. */
export function arrowsAvailable(): boolean {
    return !!process.stdin.isTTY && !!process.stdout.isTTY && typeof process.stdin.setRawMode === 'function' && process.env.TERM !== 'dumb' && !process.env.MIA_NUMBERS;
}

let cursorGuard = false;

/** Draw a Picker in place and wait for a choice. The caller must not have a readline interface reading stdin meanwhile. */
export function pickTTY(title: string, items: Choice[], opts: PickOpts = {}): Promise<PickResult> {
    const input = process.stdin;
    const output = process.stdout;
    const p = new Picker(title, items, opts);
    if (!cursorGuard) {
        cursorGuard = true;
        process.once('exit', () => output.write('\x1b[?25h'));
    }
    readline.emitKeypressEvents(input);
    const wasRaw = input.isRaw;
    input.setRawMode(true);
    input.resume();
    output.write('\x1b[?25l');
    let drawn = 0;
    const draw = () => {
        const lines = p.render(output.columns || 100, output.rows || 30);
        output.write(`${drawn ? `\x1b[${drawn}A\r` : ''}\x1b[J${lines.join('\n')}\n`);
        drawn = lines.length;
    };
    draw();
    return new Promise((resolve) => {
        const onResize = () => draw();
        const onKey = (str: string | undefined, key: Key) => {
            const r = p.key(str, key);
            if (!r) return draw();
            input.off('keypress', onKey);
            output.off('resize', onResize);
            input.setRawMode(wasRaw);
            input.pause();
            // leave one line in the scrollback: what was chosen
            output.write(`\x1b[${drawn}A\r\x1b[J\x1b[?25h`);
            if (opts.echo === false) return resolve(r);
            if (r.kind === 'select') output.write(`${c.gray(strip(title))} ${c.cyan('›')} ${strip(p.all[r.index].label).trim()}\n`);
            if (r.kind === 'text') output.write(`${c.gray(strip(title))} ${c.cyan('›')} ${r.text}\n`);
            if (r.kind === 'many') output.write(`${c.gray(strip(title))} ${c.cyan('›')} ${r.indexes.map((i) => strip(items[i].label).trim()).join(', ') || c.gray('ничего')}\n`);
            resolve(r);
        };
        input.on('keypress', onKey);
        output.on('resize', onResize);
    });
}

/**
 * Wait for one key on a terminal: one of `keys` (either keyboard layout is the caller's business),
 * Enter / Esc → '' , Ctrl+C → 'cancel'. Nothing is drawn: the caller printed the choices.
 */
export function keyTTY(keys: string[]): Promise<string> {
    const input = process.stdin;
    readline.emitKeypressEvents(input);
    const wasRaw = input.isRaw;
    input.setRawMode(true);
    input.resume();
    return new Promise((resolve) => {
        const done = (v: string) => {
            input.off('keypress', onKey);
            input.setRawMode(wasRaw);
            input.pause();
            resolve(v);
        };
        const onKey = (str: string | undefined, key: Key = {}) => {
            if (key.ctrl && (key.name === 'c' || key.name === 'd')) return done('cancel');
            if (key.name === 'return' || key.name === 'enter' || key.name === 'escape') return done('');
            const k = (str ?? '').toLowerCase();
            if (k && keys.includes(k)) done(k);
        };
        input.on('keypress', onKey);
    });
}
