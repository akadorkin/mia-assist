import { Document, isMap, isScalar, isSeq, parseDocument } from 'yaml';

/**
 * Edits of the fleet's small registry files (Prometheus overrides / keep lists, log-collector inventory,
 * whitelist arrays in scripts): "do for the new node what is there for the template node" (clone) and
 * "take the removed node out" (remove). An entry matches when its text contains the needle.
 */
export type EditOp = { op: 'clone' | 'replace'; match: string; replace: Record<string, string> } | { op: 'remove'; match: string };
export type Format = 'lines' | 'json' | 'yaml';

export function detectFormat(path: string, text: string): Format {
    if (/\.json$/i.test(path) || /^\s*[[{]/.test(text)) return 'json';
    if (/\.ya?ml$/i.test(path)) return 'yaml';
    return 'lines';
}

const swap = (s: string, rep: Record<string, string>) => Object.entries(rep).reduce((acc, [a, b]) => acc.split(a).join(b), s);

function deepSwap<T>(v: T, rep: Record<string, string>): T {
    return JSON.parse(swap(JSON.stringify(v), Object.fromEntries(Object.entries(rep).map(([a, b]) => [JSON.stringify(a).slice(1, -1), JSON.stringify(b).slice(1, -1)])))) as T;
}

/** Returns the new text and how many entries changed; an entry that already exists in its cloned form is not duplicated. */
export function editText(text: string, format: Format, e: EditOp): { text: string; changed: number; notes: string[] } {
    const notes: string[] = [];
    if (e.op === 'replace') {
        // in place, only inside the entries that match (a line, a JSON/YAML item or key)
        if (format === 'lines') {
            let changed = 0;
            const out = text.split('\n').map((l) => {
                if (!l.includes(e.match) || /^\s*#/.test(l)) return l;
                const c = swap(l, e.replace);
                if (c !== l) changed++;
                return c;
            });
            return { text: out.join('\n'), changed, notes };
        }
        if (format === 'json') {
            let changed = 0;
            const walk = (v: unknown): unknown => {
                if (Array.isArray(v)) return v.map((x) => (JSON.stringify(x).includes(e.match) ? (changed++, deepSwap(x, e.replace)) : walk(x)));
                if (v && typeof v === 'object') {
                    const out: Record<string, unknown> = {};
                    for (const [k, val] of Object.entries(v)) {
                        if (k.includes(e.match)) {
                            out[swap(k, e.replace)] = deepSwap(val, e.replace);
                            changed++;
                        } else out[k] = walk(val);
                    }
                    return out;
                }
                return v;
            };
            const next = walk(JSON.parse(text));
            const indent = text.match(/^[{[]\n(\s+)/)?.[1] ?? '  ';
            return { text: JSON.stringify(next, null, indent.includes('\t') ? '\t' : indent.length) + (text.endsWith('\n') ? '\n' : ''), changed, notes };
        }
        const doc: Document = parseDocument(text);
        let changed = 0;
        const plain = (x: unknown) => (isScalar(x) ? x.value : (x as { toJSON?: () => unknown })?.toJSON?.() ?? x);
        const visit = (node: unknown) => {
            if (isSeq(node)) {
                node.items.forEach((item, i) => {
                    if (!JSON.stringify(plain(item)).includes(e.match)) return visit(item);
                    const n = doc.createNode(deepSwap(plain(item), e.replace));
                    if (isMap(n) && isMap(item)) n.flow = item.flow;
                    const it = item as { comment?: string; commentBefore?: string };
                    Object.assign(n, { comment: it.comment, commentBefore: it.commentBefore });
                    node.items[i] = n;
                    changed++;
                });
            } else if (isMap(node)) {
                for (const pair of node.items) {
                    const key = String(isScalar(pair.key) ? pair.key.value : pair.key);
                    if (!key.includes(e.match)) {
                        visit(pair.value);
                        continue;
                    }
                    if (isScalar(pair.key)) pair.key.value = swap(key, e.replace);
                    pair.value = doc.createNode(deepSwap(plain(pair.value), e.replace));
                    changed++;
                }
            }
        };
        visit(doc.contents);
        return { text: doc.toString({ lineWidth: 0, flowCollectionPadding: false }), changed, notes };
    }
    if (format === 'lines') {
        const lines = text.split('\n');
        const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(e.match);
        const ipCount = (l: string) => (l.match(/\b\d+\.\d+\.\d+\.\d+\b/g) ?? []).length;
        // an IP inside a list on one line ("a" "b" / 'a', 'b' / a b): edit the token, not the whole line
        const token = (l: string) => {
            const re = new RegExp(`(["']?)${e.match.replace(/\./g, '\\.')}(?![\\d.])\\1`);
            const m = l.match(re);
            return m ? { at: m.index!, tok: m[0], quote: m[1] } : undefined;
        };
        const out: string[] = [];
        let changed = 0;
        for (const l of lines) {
            const hit = l.includes(e.match) && !/^\s*#/.test(l);
            if (!hit) {
                out.push(l);
                continue;
            }
            const inline = isIp && ipCount(l) > 1 ? token(l) : undefined;
            if (e.op === 'remove') {
                if (inline) {
                    const before = l.slice(0, inline.at);
                    const after = l.slice(inline.at + inline.tok.length);
                    // drop the token with one separator (the one before it, or after it when it is first)
                    const sepBefore = before.match(/(\s*,\s*|\s+)$/)?.[0] ?? '';
                    const sepAfter = after.match(/^(\s*,\s*|\s+)/)?.[0] ?? '';
                    const nl = sepBefore && !/[[(={]\s*$/.test(before.slice(0, before.length - sepBefore.length) + ' ') ? before.slice(0, before.length - sepBefore.length) + after : before + after.slice(sepAfter.length);
                    out.push(nl);
                } else if (!isIp || ipCount(l) <= 1) {
                    /* whole line goes */
                } else out.push(l);
                changed++;
                continue;
            }
            out.push(l);
            if (inline) {
                const next = swap(e.match, e.replace);
                if (l.includes(next)) continue;
                const after = l.slice(inline.at + inline.tok.length);
                const sep = after.match(/^(\s*,\s*)/)?.[0] ?? l.slice(0, inline.at).match(/(\s*,\s*)["']?$/)?.[1] ?? ' ';
                out[out.length - 1] = `${l.slice(0, inline.at + inline.tok.length)}${sep}${inline.quote}${next}${inline.quote}${after}`;
                changed++;
                continue;
            }
            const c = swap(l, e.replace);
            if (c === l) notes.push(`line unchanged by the replacements: ${l.trim().slice(0, 80)}`);
            else if (!lines.includes(c)) {
                out.push(c);
                changed++;
            }
        }
        return { text: out.join('\n'), changed, notes };
    }
    if (format === 'json') {
        const data = JSON.parse(text);
        let changed = 0;
        const walk = (v: unknown): unknown => {
            if (Array.isArray(v)) {
                const out: unknown[] = [];
                const has = (x: unknown) => v.some((y) => JSON.stringify(y) === JSON.stringify(x));
                for (const item of v) {
                    const hit = JSON.stringify(item).includes(e.match);
                    if (e.op === 'remove' && hit) {
                        changed++;
                        continue;
                    }
                    out.push(walk(item));
                    if (e.op === 'clone' && hit) {
                        const c = deepSwap(item, e.replace);
                        if (!has(c)) {
                            out.push(c);
                            changed++;
                        }
                    }
                }
                return out;
            }
            if (v && typeof v === 'object') {
                const out: Record<string, unknown> = {};
                for (const [k, val] of Object.entries(v)) {
                    if (e.op === 'remove' && k.includes(e.match)) {
                        changed++;
                        continue;
                    }
                    out[k] = walk(val);
                    if (e.op === 'clone' && k.includes(e.match)) {
                        const nk = swap(k, e.replace);
                        if (!(nk in (v as Record<string, unknown>)) && nk !== k) {
                            out[nk] = deepSwap(val, e.replace);
                            changed++;
                        }
                    }
                }
                return out;
            }
            return v;
        };
        const next = walk(data);
        const indent = text.match(/^[{[]\n(\s+)/)?.[1] ?? '  ';
        return { text: JSON.stringify(next, null, indent.includes('\t') ? '\t' : indent.length) + (text.endsWith('\n') ? '\n' : ''), changed, notes };
    }
    // yaml: sequences of items / map keys, comments kept
    const doc: Document = parseDocument(text);
    let changed = 0;
    const visit = (node: unknown) => {
        if (isSeq(node)) {
            for (let i = node.items.length - 1; i >= 0; i--) {
                const item = node.items[i];
                const hit = JSON.stringify(isScalar(item) ? item.value : (item as { toJSON?: () => unknown })?.toJSON?.() ?? item).includes(e.match);
                if (!hit) {
                    visit(item);
                    continue;
                }
                if (e.op === 'remove') {
                    node.items.splice(i, 1);
                    changed++;
                } else {
                    const plain = isScalar(item) ? item.value : (item as { toJSON: () => unknown }).toJSON();
                    const c = deepSwap(plain, e.replace);
                    const exists = node.items.some((x) => JSON.stringify(isScalar(x) ? x.value : (x as { toJSON: () => unknown }).toJSON()) === JSON.stringify(c));
                    if (!exists) {
                        const n = doc.createNode(c);
                        if (isMap(n) && isMap(item)) n.flow = item.flow;
                        node.items.splice(i + 1, 0, n);
                        changed++;
                    }
                }
            }
        } else if (isMap(node)) {
            for (let i = node.items.length - 1; i >= 0; i--) {
                const pair = node.items[i];
                const key = String(isScalar(pair.key) ? pair.key.value : pair.key);
                if (key.includes(e.match)) {
                    if (e.op === 'remove') {
                        node.items.splice(i, 1);
                        changed++;
                    } else {
                        const nk = swap(key, e.replace);
                        if (nk !== key && !node.has(nk)) {
                            node.items.splice(i + 1, 0, doc.createPair(nk, deepSwap((pair.value as { toJSON?: () => unknown })?.toJSON?.() ?? (isScalar(pair.value) ? pair.value.value : pair.value), e.replace)) as (typeof node.items)[number]);
                            changed++;
                        }
                    }
                } else visit(pair.value);
            }
        }
    };
    visit(doc.contents);
    return { text: doc.toString({ lineWidth: 0, flowCollectionPadding: false }), changed, notes };
}
