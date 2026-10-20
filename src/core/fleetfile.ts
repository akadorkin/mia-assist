import fs from 'node:fs';
import path from 'node:path';
import { Document, Node, isMap, isScalar, isSeq, parse as parseYaml, parseDocument } from 'yaml';
import { Inventory } from './inventory.js';
import { hashOf } from './plan.js';
import { lineDiff, preserveLayout } from './scenario.js';

/**
 * Edits of fleet.yaml that keep the owner's layout and comments: hosts added, changed, switched off,
 * removed, moved between groups. Every edit is a plan first (diff + hash), written only when confirmed,
 * with a backup in the state directory.
 */

export function addToGroup(doc: Document, group: string, name: string): boolean {
    const seq = doc.getIn(['groups', group]);
    if (!isSeq(seq)) return false;
    if (seq.items.some((i) => String((i as { value?: unknown }).value ?? i) === name)) return false;
    seq.add(doc.createNode(name));
    return true;
}

export function removeFromGroups(doc: Document, name: string): string[] {
    const groups = doc.get('groups');
    const hit: string[] = [];
    if (!isMap(groups)) return hit;
    for (const pair of groups.items) {
        const seq = pair.value;
        if (!isSeq(seq)) continue;
        const i = seq.items.findIndex((x) => String((x as { value?: unknown }).value ?? x) === name);
        if (i >= 0) {
            seq.items.splice(i, 1);
            hit.push(String((pair.key as { value?: unknown }).value ?? pair.key));
        }
    }
    return hit;
}

export function groupsOf(doc: Document, name: string): string[] {
    const groups = doc.get('groups');
    if (!isMap(groups)) return [];
    return groups.items
        .filter((p) => isSeq(p.value) && p.value.items.some((x) => String((x as { value?: unknown }).value ?? x) === name))
        .map((p) => String((p.key as { value?: unknown }).value ?? p.key));
}


/** Write lists of scalars and small objects inside lists as [a, b] / {k: v}, like the rest of fleet.yaml. */
export function flowStyle(node: unknown, inSeq = false): unknown {
    if (isSeq(node)) {
        if (node.items.every((i) => isScalar(i))) node.flow = true;
        for (const i of node.items) flowStyle(i, true);
    } else if (isMap(node)) {
        if (inSeq && node.items.every((p) => isScalar(p.value))) node.flow = true;
        for (const p of node.items) flowStyle(p.value);
    }
    return node as Node;
}

/** Fields of a host entry that the console and fleet_host_edit may set. */
export const HOST_FIELDS = ['address', 'user', 'port', 'sudo', 'roles', 'tags', 'domain', 'panelNode', 'title', 'provider', 'notes'] as const;
export type HostField = (typeof HOST_FIELDS)[number];
export type HostFields = Partial<Record<HostField, string | number | boolean | string[]>>;

export type HostOp = 'add' | 'update' | 'remove' | 'disable' | 'enable';

export interface HostEdit {
    op: HostOp;
    name: string;
    set?: HostFields;
    unset?: HostField[];
    /** Full group membership after the edit (groups that do not exist yet are created). */
    groups?: string[];
}

const key = (x: unknown) => String((x as { value?: unknown }).value ?? x);
const show = (v: unknown) => (Array.isArray(v) ? `[${v.join(', ')}]` : String(v));

function removeFromGroup(doc: Document, group: string, name: string): boolean {
    const seq = doc.getIn(['groups', group]);
    if (!isSeq(seq)) return false;
    const i = seq.items.findIndex((x) => key(x) === name);
    if (i < 0) return false;
    seq.items.splice(i, 1);
    return true;
}

/** Make the host a member of exactly these groups; groups that do not exist yet are created. */
function setGroups(doc: Document, name: string, want: string[]): string[] {
    const changes: string[] = [];
    const now = groupsOf(doc, name);
    for (const g of now.filter((g) => !want.includes(g))) if (removeFromGroup(doc, g, name)) changes.push(`из группы ${g}`);
    for (const g of want.filter((g) => !now.includes(g))) {
        if (!/^[\w.-]+$/.test(g)) throw new Error(`имя группы «${g}»: только буквы, цифры, . _ -`);
        if (addToGroup(doc, g, name)) {
            changes.push(`в группу ${g}`);
            continue;
        }
        if (!isMap(doc.get('groups'))) doc.set('groups', doc.createNode({}));
        const groups = doc.get('groups');
        if (isMap(groups)) groups.flow = false;
        doc.setIn(['groups', g], flowStyle(doc.createNode([name])));
        changes.push(`новая группа ${g}`);
    }
    return changes;
}

/** Change the parsed fleet.yaml; one summary line per edit. Throws on an edit that cannot be made. */
export function applyHostEdits(doc: Document, edits: HostEdit[]): string[] {
    const out: string[] = [];
    for (const e of edits) {
        if (!/^[\w.-]+$/.test(e.name)) throw new Error(`имя хоста «${e.name}»: только буквы, цифры, . _ -`);
        const hosts = doc.get('hosts');
        const exists = isMap(hosts) && hosts.has(e.name);
        if (e.op === 'add') {
            if (exists) throw new Error(`хост ${e.name} уже есть в fleet.yaml — используйте изменение`);
            if (doc.getIn(['groups', e.name]) !== undefined) throw new Error(`«${e.name}» — это имя группы`);
            const entry = Object.fromEntries(HOST_FIELDS.filter((k) => e.set?.[k] !== undefined && e.set[k] !== '' && !(Array.isArray(e.set[k]) && !(e.set[k] as string[]).length)).map((k) => [k, e.set![k]]));
            if (!isMap(hosts)) doc.set('hosts', doc.createNode({}));
            const map = doc.get('hosts');
            if (isMap(map)) map.flow = false;
            doc.setIn(['hosts', e.name], flowStyle(doc.createNode(entry)));
            const groups = e.groups ? setGroups(doc, e.name, e.groups) : [];
            out.push(`hosts.${e.name} добавлен${Object.keys(entry).length ? `: ${Object.entries(entry).map(([k, v]) => `${k} ${show(v)}`).join(', ')}` : ''}${groups.length ? `; ${groups.join('; ')}` : ''}`);
        } else {
            if (!exists) throw new Error(`хоста ${e.name} нет в fleet.yaml`);
            if (e.op === 'remove') {
                doc.deleteIn(['hosts', e.name]);
                const gone = removeFromGroups(doc, e.name);
                out.push(`hosts.${e.name} удалён${gone.length ? `, убран из групп: ${gone.join(', ')}` : ''}`);
                continue;
            }
            if (!isMap(doc.getIn(['hosts', e.name]))) doc.setIn(['hosts', e.name], doc.createNode({}));
            const changes: string[] = [];
            const set: Record<string, unknown> = { ...(e.set ?? {}) };
            const unset = [...(e.unset ?? [])] as string[];
            if (e.op === 'disable') set.disabled = true;
            if (e.op === 'enable') unset.push('disabled');
            for (const [k, v] of Object.entries(set)) {
                if (v === undefined) continue;
                const was = doc.getIn(['hosts', e.name, k]);
                const before = isSeq(was) ? was.toJSON() : isScalar(was) ? was.value : was;
                if (JSON.stringify(before) === JSON.stringify(v)) continue;
                doc.setIn(['hosts', e.name, k], flowStyle(doc.createNode(v)));
                changes.push(`${k}: ${before === undefined ? '—' : show(before)} → ${show(v)}`);
            }
            for (const k of unset) {
                if (doc.getIn(['hosts', e.name, k]) === undefined) continue;
                doc.deleteIn(['hosts', e.name, k]);
                changes.push(k === 'disabled' ? 'снова включён' : `${k} убран`);
            }
            if (e.groups) changes.push(...setGroups(doc, e.name, e.groups));
            out.push(`hosts.${e.name}: ${e.op === 'disable' && changes.length ? 'отключён' : changes.join('; ') || 'без изменений'}`);
        }
    }
    return out;
}

export interface FleetPlan {
    file: string;
    before: string;
    after: string;
    diff: string[];
    summary: string[];
    /** Changes when the file or the edit changes: apply only what was shown. */
    hash: string;
}

const EMPTY = 'hosts: {}\n';

export function readFleet(file: string): string {
    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : EMPTY;
}

/** Dry run of host edits: the new text (layout kept), its diff, and a check that mia can still load it. */
export function planFleet(file: string, edits: HostEdit[]): FleetPlan {
    const before = readFleet(file);
    const doc = parseDocument(before);
    if (doc.errors.length) throw new Error(`${file}: ошибка YAML: ${doc.errors[0].message}`);
    const summary = applyHostEdits(doc, edits);
    const want = JSON.stringify(doc.toJSON());
    // line surgery keeps every other byte of the owner's file; the whole-document rewrite is the fallback
    const cut = surgical(before, edits);
    const after = cut !== undefined && JSON.stringify(parseYaml(cut)) === want ? cut : preserveLayout(before, doc.toString({ lineWidth: 0, flowCollectionPadding: false }));
    new Inventory(file, parseYaml(after)); // throws with the reason when the result would not load
    return { file, before, after, diff: lineDiff(before, after), summary, hash: hashOf([file, before, after]) };
}

// ------------------------------------------------------------------ line surgery

interface Section {
    header: number;
    /** first line after the section (next top-level key) */
    end: number;
}

const indentOf = (l: string) => l.match(/^\s*/)![0].length;
const isLayout = (l: string) => !l.trim() || /^\s*#/.test(l);

function sectionOf(lines: string[], key: string): Section | undefined {
    const header = lines.findIndex((l) => new RegExp(`^${key}:\\s*(#.*)?$`).test(l));
    if (header < 0) return undefined;
    let end = header + 1;
    while (end < lines.length && !/^[^\s#]/.test(lines[end])) end++;
    return { header, end };
}

/** Entries of a block map section: name and its lines [start, end) without the blank/comment lines after it. */
function entriesOf(lines: string[], sec: Section): { indent: number; list: Array<{ name: string; start: number; end: number }> } | undefined {
    const keyRe = /^(\s+)([\w.-]+):(\s|$)/;
    const idx: number[] = [];
    let indent = Infinity;
    for (let i = sec.header + 1; i < sec.end; i++) {
        const m = lines[i].match(keyRe);
        if (m && !isLayout(lines[i])) indent = Math.min(indent, m[1].length);
    }
    if (indent === Infinity) return undefined;
    for (let i = sec.header + 1; i < sec.end; i++) if (indentOf(lines[i]) === indent && keyRe.test(lines[i])) idx.push(i);
    const list = idx.map((start, k) => {
        let end = k + 1 < idx.length ? idx[k + 1] : sec.end;
        while (end > start + 1 && isLayout(lines[end - 1]) && (!lines[end - 1].trim() || indentOf(lines[end - 1]) <= indent)) end--;
        return { name: lines[start].match(keyRe)![2], start, end };
    });
    return { indent, list };
}

/** A map entry as fleet.yaml writes it: lists in flow style, indented under its section. */
function entryLines(name: string, value: unknown, indent: number): string[] {
    const d = new Document({ [name]: value });
    flowStyle(d.contents);
    return d
        .toString({ lineWidth: 0, flowCollectionPadding: false })
        .trimEnd()
        .split('\n')
        .map((l) => ' '.repeat(indent) + l);
}

/** Put a member into / take it out of one group, in the style the group is written in. */
function groupEdit(lines: string[], group: string, name: string, add: boolean): boolean {
    let sec = sectionOf(lines, 'groups');
    const esc = group.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (sec) {
        for (let i = sec.header + 1; i < sec.end; i++) {
            const flow = lines[i].match(new RegExp(`^(\\s+)${esc}:(\\s*)\\[(.*?)\\](\\s*)(#.*)?$`));
            if (flow) {
                const items = flow[3].split(',').map((x) => x.trim()).filter(Boolean);
                const next = add ? (items.includes(name) ? items : [...items, name]) : items.filter((x) => x !== name);
                const code = `${flow[1]}${group}:${flow[2] || ' '}[${next.join(', ')}]`;
                const col = flow[5] ? lines[i].lastIndexOf(flow[5]) : -1;
                lines[i] = flow[5] ? (col > code.length ? code.padEnd(col) + flow[5] : `${code}${flow[4] || ' '}${flow[5]}`) : code;
                return true;
            }
            if (new RegExp(`^(\\s+)${esc}:\\s*(#.*)?$`).test(lines[i])) {
                let j = i + 1;
                const items: number[] = [];
                while (j < sec.end && (isLayout(lines[j]) || /^\s+-\s/.test(lines[j]))) {
                    if (/^\s+-\s/.test(lines[j])) items.push(j);
                    j++;
                }
                if (!items.length) return false;
                const hit = items.find((k) => lines[k].replace(/#.*$/, '').replace(/^\s+-\s+/, '').trim().replace(/^['"]|['"]$/g, '') === name);
                if (add) {
                    if (hit === undefined) lines.splice(items[items.length - 1] + 1, 0, `${lines[items[0]].match(/^\s+-\s+/)![0]}${name}`);
                } else if (hit !== undefined) lines.splice(hit, 1);
                return true;
            }
        }
    }
    if (!add) return true;
    // a new group: after the last one, or a new groups section before hosts
    if (sec) {
        const e = entriesOf(lines, sec);
        const at = e?.list.length ? e.list[e.list.length - 1].end : sec.header + 1;
        lines.splice(at, 0, `${' '.repeat(e?.indent ?? 2)}${group}: [${name}]`);
        return true;
    }
    const hosts = sectionOf(lines, 'hosts');
    if (!hosts) return false;
    lines.splice(hosts.header, 0, 'groups:', `  ${group}: [${name}]`, '');
    sec = sectionOf(lines, 'groups');
    return !!sec;
}

/** The whole edit as line surgery, or undefined when the file is not laid out the usual way. */
function surgical(before: string, edits: HostEdit[]): string | undefined {
    const lines = before.replace(/\n$/, '').split('\n');
    for (const e of edits) {
        const sec = sectionOf(lines, 'hosts');
        if (!sec) return undefined;
        const ent = entriesOf(lines, sec);
        const cur = ent?.list.find((x) => x.name === e.name);
        if (e.op === 'add') {
            const value = Object.fromEntries(HOST_FIELDS.filter((k) => e.set?.[k] !== undefined && e.set[k] !== '' && !(Array.isArray(e.set[k]) && !(e.set[k] as string[]).length)).map((k) => [k, e.set![k]]));
            const indent = ent?.indent ?? 2;
            const last = ent?.list[ent.list.length - 1];
            // blank lines between hosts in this file → one before the new host too
            const spaced = !!ent?.list.slice(1).some((x) => !lines[x.start - 1].trim());
            const at = last ? last.end : sec.header + 1;
            lines.splice(at, 0, ...(last && spaced ? [''] : []), ...entryLines(e.name, value, indent));
        } else {
            if (!cur || !ent) return undefined;
            if (e.op === 'remove') {
                let { start, end } = cur;
                // a comment right above the host (no blank line between) is about it
                while (start - 1 > sec.header && /^\s*#/.test(lines[start - 1]) && indentOf(lines[start - 1]) === ent.indent) start--;
                if (start > 0 && !lines[start - 1].trim() && (end >= lines.length || !lines[end].trim())) start--;
                else if (start - 1 === sec.header && end < lines.length && !lines[end].trim()) end++;
                lines.splice(start, end - start);
            } else {
                // only this host's lines are rewritten (its own comments kept by preserveLayout)
                const pad = ' '.repeat(ent.indent);
                const old = lines.slice(cur.start, cur.end).map((l) => (l.startsWith(pad) ? l.slice(ent.indent) : l.trimStart()));
                const d = parseDocument(old.join('\n') + '\n');
                if (d.errors.length || !isMap(d.getIn([e.name]))) return undefined;
                for (const [k, v] of Object.entries(e.set ?? {})) if (v !== undefined) d.setIn([e.name, k], flowStyle(d.createNode(v)));
                for (const k of e.unset ?? []) d.deleteIn([e.name, k]);
                if (e.op === 'disable') d.setIn([e.name, 'disabled'], true);
                if (e.op === 'enable') d.deleteIn([e.name, 'disabled']);
                const next = preserveLayout(old.join('\n'), d.toString({ lineWidth: 0, flowCollectionPadding: false }).trimEnd());
                lines.splice(cur.start, cur.end - cur.start, ...next.split('\n').map((l) => (l ? pad + l : l)));
            }
        }
        if (e.op === 'remove') {
            for (const g of groupNames(lines)) if (!groupEdit(lines, g, e.name, false)) return undefined;
        } else if (e.groups) {
            const now = groupNames(lines).filter((g) => groupHas(lines, g, e.name));
            for (const g of now.filter((g) => !e.groups!.includes(g))) if (!groupEdit(lines, g, e.name, false)) return undefined;
            for (const g of e.groups.filter((g) => !now.includes(g))) if (!groupEdit(lines, g, e.name, true)) return undefined;
        }
    }
    return lines.join('\n') + '\n';
}

function groupNames(lines: string[]): string[] {
    const sec = sectionOf(lines, 'groups');
    return sec ? (entriesOf(lines, sec)?.list.map((x) => x.name) ?? []) : [];
}

function groupHas(lines: string[], group: string, name: string): boolean {
    const g = parseDocument(lines.join('\n')).getIn(['groups', group]);
    return isSeq(g) && g.items.some((x) => key(x) === name);
}

/** Write a planned edit if fleet.yaml is still what the plan was made from; the old file goes to <stateDir>/backups. */
export function writeFleet(plan: FleetPlan, stateDir: string): { backup?: string } {
    if (readFleet(plan.file) !== plan.before) throw new Error('fleet.yaml изменился после показа плана — постройте план заново');
    let backup: string | undefined;
    if (fs.existsSync(plan.file)) {
        const dir = path.join(stateDir, 'backups');
        fs.mkdirSync(dir, { recursive: true });
        backup = path.join(dir, `${path.basename(plan.file)}.${new Date().toISOString().replace(/[:.]/g, '-')}`);
        fs.copyFileSync(plan.file, backup);
    }
    fs.mkdirSync(path.dirname(plan.file), { recursive: true });
    fs.writeFileSync(plan.file, plan.after);
    return { backup };
}
