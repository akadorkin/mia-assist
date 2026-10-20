/** ANSI colours for the terminal; off when stdout is not a TTY or NO_COLOR is set (FORCE_COLOR turns them on). */
const on = !!process.env.FORCE_COLOR || (!!process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb');

const wrap = (open: number, close: number) => (s: string) => (on && s ? `\x1b[${open}m${s}\x1b[${close}m` : s);

export const c = {
    on,
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    blue: wrap(34, 39),
    magenta: wrap(35, 39),
    cyan: wrap(36, 39),
    gray: wrap(90, 39),
};

export const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

/**
 * Symbols some terminals draw two cells wide (iTerm «ambiguous characters are double-width», some
 * fonts): counted as 2, so a clipped line never wraps and in-place redraws stay in place.
 */
const WIDE = /[…—–·▶❯◉◯●○✔✖▲→↺✎│─┼◆◇└◐◓◑◒░█▸]/;
const cw = (ch: string) => (WIDE.test(ch) ? 2 : 1);

/** Width on screen, colour codes left out, the symbols above counted as two cells. */
export const vwidth = (s: string) => [...strip(s)].reduce((n, ch) => n + cw(ch), 0);

/**
 * Cut to w cells (colour codes do not count), ending with … and a colour reset. wide: count the symbols
 * above as two cells (lines redrawn in place); tables measure plain characters and pass false.
 */
export function clipVisible(s: string, w: number, wide = true): string {
    const cw = (ch: string) => (wide && WIDE.test(ch) ? 2 : 1);
    if ([...strip(s)].reduce((n, ch) => n + cw(ch), 0) <= w) return s;
    let out = '';
    let vis = 0;
    for (let i = 0; i < s.length; ) {
        const m = s.slice(i).match(/^\x1b\[[0-9;]*m/);
        if (m) {
            out += m[0];
            i += m[0].length;
            continue;
        }
        const ch = String.fromCodePoint(s.codePointAt(i)!);
        // room for the «…» itself (two cells where it may be drawn wide)
        if (vis + cw(ch) > w - cw('…')) break;
        out += ch;
        vis += cw(ch);
        i += ch.length;
    }
    return `${out}…${on ? '\x1b[0m' : ''}`;
}

// \b is ASCII-only in JS: Cyrillic words need Unicode-aware edges
const word = (list: string) => new RegExp(`(?<![\\p{L}\\d_])(?:${list})(?![\\p{L}\\d_])`, 'u');
const BAD = word('CRIT|КРИТ|НЕДОСТУПЕН|UNREACHABLE|ОШИБКА|FAIL|ERROR|ИСТЁК|EXPIRED|DISCONNECTED|failed|exited|dead');
const WARN = word('WARN|ВНИМ|внимание|warn|не в сети|offline|нет в fleet\\.yaml|restarting|connecting|пропущено|blocked|не задано|не задана');
const GOOD = new RegExp(`^(?:${'ok|да|yes|active|running|connected|в сети|выполнено|пройдено|сделано|applied|есть'})(?![\\p{L}\\d_])`, 'u');

/** Colour one table cell / status word by what it says. */
export function tone(s: string): string {
    if (!on || !s) return s;
    if (BAD.test(s)) return c.red(s);
    if (WARN.test(s)) return c.yellow(s);
    if (GOOD.test(s.trim())) return c.green(s);
    return s;
}

function scalar(v: string): string {
    const t = v.trim();
    if (!t) return v;
    if (/^(true|false|null|да|нет)$/.test(t)) return c.yellow(v);
    if (/^-?\d+(\.\d+)?(%|d|h|m|s|ms|GiB|MB)?$/.test(t)) return c.magenta(v);
    if (BAD.test(t)) return c.red(v);
    return v;
}

/** YAML with colour: keys, numbers/booleans, diff lines (- removed, + added), comments. */
export function hlYaml(text: string): string {
    if (!on) return text;
    return text
        .split('\n')
        .map((line) => {
            // lineDiff output, possibly quoted inside a YAML list: "- '- old'" / "- '+   12: new'"
            const diff = line.match(/^(\s*-\s+)(['"]?)([-+])(\s.*)$/);
            if (diff) return `${c.gray(diff[1])}${diff[2]}${diff[3] === '+' ? c.green(diff[3] + diff[4]) : c.red(diff[3] + diff[4])}`;
            if (/^\s*#/.test(line)) return c.gray(line);
            const kv = line.match(/^(\s*(?:-\s+)?)([^\s:#'"][^:#]*?|'[^']*'|"[^"]*"):(\s|$)(.*)$/);
            if (kv) return `${c.gray(kv[1])}${c.cyan(kv[2])}:${kv[3]}${scalar(kv[4])}`;
            const item = line.match(/^(\s*-\s+)(.*)$/);
            if (item) return `${c.gray(item[1])}${scalar(item[2])}`;
            return line;
        })
        .join('\n');
}
