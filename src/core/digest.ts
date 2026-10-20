import fs from 'node:fs';
import path from 'node:path';
import { redactText } from './output.js';

/**
 * Digest of Claude Code transcripts (~/.claude/projects/<project>/<session>.jsonl): what was asked,
 * what was run where, which files were touched — and the hosts, IPs, domains, paths, containers
 * and units mentioned across all sessions. Read-only; every string goes through redaction.
 */

export interface SessionDigest {
    id: string;
    project: string;
    file: string;
    cwd?: string;
    first?: string;
    last?: string;
    title?: string;
    prompts: string[];
    notes: string[];
    commands: string[];
    files: string[];
}

export type Entities = Record<string, Map<string, Set<string>>>;

const MAX_PROMPT = 2000;
const MAX_NOTE = 600;
const MAX_CMD = 500;

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) + ` … (+${s.length - n} chars)` : s);

/** Extra redaction for transcripts: private key blocks and long opaque tokens next to key-ish words. */
export function scrub(s: string): string {
    return redactText(s)
        .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '«private key redacted»')
        .replace(/((?:key|token|secret|password|passwd|pass|pwd)[^\n]{0,12}?[\s:=]["']?)[A-Za-z0-9+/_.-]{24,}/gi, '$1«redacted»')
        .replace(/\b(ghp|gho|github_pat|glpat|xox[bap]|sk-(?:ant-)?)[A-Za-z0-9_-]{10,}/g, '$1«redacted»')
        // base64 JSON / JWTs (the remnanode SECRET_KEY looks like this)
        .replace(/\beyJ[A-Za-z0-9+/_=.-]{16,}/g, '«redacted»')
        // long opaque tokens: mixed case AND digits (hex hashes and uuids stay readable)
        .replace(/[A-Za-z0-9+/_=-]{32,}/g, (t) => (/[a-z]/.test(t) && /[A-Z]/.test(t) && /\d/.test(t) && !/^[\/]/.test(t) ? '«redacted»' : t));
}

function textOf(content: unknown): string {
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) return content.map((c) => (c && typeof c === 'object' && (c as { type?: string }).type === 'text' ? (c as { text: string }).text : '')).join('\n');
    return '';
}

export function digestSession(file: string): SessionDigest {
    const d: SessionDigest = { id: path.basename(file, '.jsonl'), project: path.basename(path.dirname(file)), file, prompts: [], notes: [], commands: [], files: [] };
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    for (const line of lines) {
        if (!line.trim()) continue;
        let o: Record<string, any>;
        try {
            o = JSON.parse(line);
        } catch {
            continue;
        }
        if (o.timestamp) {
            d.first ??= o.timestamp;
            d.last = o.timestamp;
        }
        if (o.cwd && !d.cwd) d.cwd = o.cwd;
        if (o.type === 'summary' && o.summary) d.title = String(o.summary);
        if (o.type === 'custom-title' && o.customTitle) d.title = String(o.customTitle);
        if (o.type === 'user' && !o.isMeta && !o.isSidechain) {
            const c = o.message?.content;
            if (Array.isArray(c) && c.some((x: any) => x?.type === 'tool_result')) continue;
            const t = textOf(c).trim();
            if (!t || t.startsWith('<') || (o.origin && o.origin.kind && o.origin.kind !== 'human')) continue;
            d.prompts.push(clip(scrub(t), MAX_PROMPT));
        }
        if (o.type === 'assistant' && !o.isSidechain && Array.isArray(o.message?.content)) {
            for (const c of o.message.content) {
                if (c?.type === 'text' && c.text?.trim()) d.notes.push(clip(scrub(c.text.trim()), MAX_NOTE));
                if (c?.type === 'tool_use') {
                    const inp = c.input ?? {};
                    if (typeof inp.command === 'string') d.commands.push(clip(scrub(inp.command), MAX_CMD));
                    if (typeof inp.file_path === 'string' && /^(Edit|Write|MultiEdit|NotebookEdit)$/.test(c.name)) d.files.push(inp.file_path);
                }
            }
        }
    }
    d.files = [...new Set(d.files)];
    d.title ??= d.prompts[0]?.split('\n')[0].slice(0, 80);
    return d;
}

const RE = {
    ipv4: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
    domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|co|ru|me|dev|app|cloud|xyz|online|site|pro|tech|ts\.net|local|lan|home|arpa|de|nl|fi|uk|eu|su|рф)\b(?!\.[a-z])/gi,
    path: /(?<![\w.])\/(?:opt|etc|srv|mnt|media|data|var\/lib|var\/log|home|root|usr\/local|volume\d*|share|storage|DATA)\/[^\s'"`;|&)<>,]*/g,
};

/** Targets of ssh invocations in a shell command (ssh at command position; options with arguments skipped). */
export function sshTargets(cmd: string): string[] {
    const out: string[] = [];
    for (const m of cmd.matchAll(/(?:^|[;&|(`]\s*|\$\(\s*|\b(?:sudo|timeout\s+\d+|exec|command)\s+)ssh\s+([^;&|\n`)]*)/g)) {
        const words = m[1].trim().split(/\s+/);
        let port: string | undefined;
        let user: string | undefined;
        for (let i = 0; i < words.length; i++) {
            const w = words[i];
            if (/^-[bcDEeFIiJLlmOoPpQRSWw]$/.test(w)) {
                if (w === '-p') port = words[i + 1];
                if (w === '-l') user = words[i + 1];
                i++;
                continue;
            }
            if (/^-p\d+$/.test(w)) {
                port = w.slice(2);
                continue;
            }
            if (w.startsWith('-')) continue;
            if (/^([\w.-]+@)?[\w.-]+$/.test(w)) out.push(`${!w.includes('@') && user ? `${user}@` : ''}${w}${port ? `:${port}` : ''}`);
            break;
        }
    }
    return out;
}

const FILE_EXT_TLD = /\.(?:py|js|ts|json|md|yml|yaml|sh|conf|log|txt|dat|pem|service|timer)$/i;

/** Collect entities from one session's commands, prompts and notes. */
export function extractEntities(d: SessionDigest, into: Entities) {
    const add = (kind: string, v: string) => {
        v = v.replace(/[.:,]+$/, '');
        if (!v) return;
        const m = (into[kind] ??= new Map());
        if (!m.has(v)) m.set(v, new Set());
        m.get(v)!.add(d.id);
    };
    const text = [...d.commands, ...d.prompts, ...d.notes].join('\n');
    for (const ip of text.match(RE.ipv4) ?? []) if (!/^(0\.|255\.|127\.0\.0\.1$)/.test(ip)) add('ips', ip);
    for (const dm of text.match(RE.domain) ?? []) if (!FILE_EXT_TLD.test(dm) && !/^(www\.)?(github|google|anthropic|claude|npmjs|docker|ubuntu|debian)\./i.test(dm)) add('domains', dm.toLowerCase());
    for (const p of text.match(RE.path) ?? []) add('paths', p.replace(/\/+$/, ''));

    for (const cmd of d.commands) {
        // ssh targets: ssh [opts] [user@]host …
        for (const t of sshTargets(cmd)) add('sshTargets', t);
        for (const m of cmd.matchAll(/\bdocker\s+(?:logs|restart|exec|inspect|stop|start|rm|stats|top|port|update)\s+(?:-{1,2}[\w-]+(?:[= ](?!-)\S+)?\s+)*([a-zA-Z][\w.-]+)/g)) add('containers', m[1]);
        for (const m of cmd.matchAll(/\bdocker(?:-compose|\s+compose)\s+(?:-p\s+\S+\s+)?-f\s+(\S+)/g)) add('composeFiles', m[1].replace(/['"]/g, ''));
        for (const m of cmd.matchAll(/\bcd\s+(\/\S+)\s*&&\s*docker(?:-compose|\s+compose)/g)) add('composeDirs', m[1].replace(/['"]/g, ''));
        for (const m of cmd.matchAll(/\bsystemctl\s+(?:--\S+\s+)*(?:status|restart|start|stop|enable|disable|reload|is-active|cat|edit)\s+(?:--\S+\s+)*([\w@.-]+)/g)) if (!/^-/.test(m[1])) add('units', m[1]);
        for (const m of cmd.matchAll(/\bjournalctl\b[^|;&]*?-u\s+([\w@.-]+)/g)) add('units', m[1]);
        for (const m of cmd.matchAll(/https?:\/\/[^\s'"`<>)]+/g)) add('urls', m[0]);
        for (const m of cmd.matchAll(/\btailscale\s+(\w+)/g)) add('tailscaleCmds', m[1]);
    }
}

export function renderSession(d: SessionDigest): string {
    const out = [
        `# ${d.title ?? d.id}`,
        '',
        `- session: ${d.id}`,
        `- project: ${d.project}${d.cwd ? ` (cwd ${d.cwd})` : ''}`,
        `- time: ${d.first ?? '?'} → ${d.last ?? '?'}`,
        `- prompts: ${d.prompts.length}, commands: ${d.commands.length}, files edited: ${d.files.length}`,
        '',
        '## Prompts (owner)',
        '',
        ...d.prompts.map((p, i) => `${i + 1}. ${p.replace(/\n/g, '\n   ')}`),
        '',
    ];
    if (d.files.length) out.push('## Files edited', '', ...d.files.map((f) => `- ${f}`), '');
    if (d.commands.length) out.push('## Commands run', '', '```sh', ...d.commands.map((c) => c.replace(/\n/g, '\n  ')), '```', '');
    if (d.notes.length) out.push('## Assistant notes (clipped)', '', ...d.notes.map((n) => `- ${n.replace(/\n/g, ' ')}`), '');
    return out.join('\n');
}

export function renderEntities(e: Entities, titles: Map<string, string>): string {
    const out = ['# Everything mentioned across sessions', '', 'Counts = sessions mentioning it. Secrets are masked.', ''];
    for (const kind of ['sshTargets', 'ips', 'domains', 'containers', 'composeFiles', 'composeDirs', 'units', 'paths', 'urls', 'tailscaleCmds']) {
        const m = e[kind];
        if (!m?.size) continue;
        out.push(`## ${kind}`, '', '| value | sessions | where |', '|---|---|---|');
        for (const [v, s] of [...m].sort((a, b) => b[1].size - a[1].size || a[0].localeCompare(b[0])).slice(0, 400)) {
            const where = [...s].slice(0, 4).map((id) => titles.get(id) ?? id.slice(0, 8)).join('; ');
            out.push(`| \`${v.replace(/\|/g, '\\|')}\` | ${s.size} | ${where.replace(/\|/g, '/')} |`);
        }
        out.push('');
    }
    return out.join('\n');
}

export function listTranscripts(dir: string): string[] {
    if (!fs.existsSync(dir)) throw new Error(`${dir} does not exist`);
    const out: string[] = [];
    for (const p of fs.readdirSync(dir)) {
        const pd = path.join(dir, p);
        if (!fs.statSync(pd).isDirectory()) continue;
        for (const f of fs.readdirSync(pd)) if (f.endsWith('.jsonl')) out.push(path.join(pd, f));
    }
    return out;
}

/** Write the digest: index.md, entities.md/.json, sessions/*.md. Returns counts. */
export function writeDigest(dir: string, outDir: string): { sessions: number; outDir: string; entities: Record<string, number> } {
    const files = listTranscripts(dir);
    const digests = files.map(digestSession).filter((d) => d.prompts.length || d.commands.length);
    digests.sort((a, b) => (a.first ?? '').localeCompare(b.first ?? ''));
    fs.mkdirSync(path.join(outDir, 'sessions'), { recursive: true, mode: 0o700 });
    const entities: Entities = {};
    const titles = new Map<string, string>();
    const index = ['# Sessions', '', '| date | title | project | prompts | cmds | file |', '|---|---|---|---|---|---|'];
    for (const d of digests) {
        extractEntities(d, entities);
        const name = `${(d.first ?? '0000').slice(0, 10)}-${(d.title ?? d.id).replace(/[^\p{L}\p{N}]+/gu, '-').slice(0, 50).replace(/^-|-$/g, '')}-${d.id.slice(0, 8)}.md`;
        titles.set(d.id, `${(d.first ?? '').slice(0, 10)} ${d.title ?? d.id}`.slice(0, 60));
        fs.writeFileSync(path.join(outDir, 'sessions', name), renderSession(d), { mode: 0o600 });
        index.push(`| ${(d.first ?? '').slice(0, 10)} | ${(d.title ?? '').replace(/\|/g, '/').slice(0, 80)} | ${d.project} | ${d.prompts.length} | ${d.commands.length} | sessions/${name} |`);
    }
    fs.writeFileSync(path.join(outDir, 'index.md'), index.join('\n') + '\n', { mode: 0o600 });
    fs.writeFileSync(path.join(outDir, 'entities.md'), renderEntities(entities, titles), { mode: 0o600 });
    const json = Object.fromEntries(Object.entries(entities).map(([k, m]) => [k, Object.fromEntries([...m].map(([v, s]) => [v, [...s]]))]));
    fs.writeFileSync(path.join(outDir, 'entities.json'), JSON.stringify(json, null, 1), { mode: 0o600 });
    return { sessions: digests.length, outDir, entities: Object.fromEntries(Object.entries(entities).map(([k, m]) => [k, m.size])) };
}
