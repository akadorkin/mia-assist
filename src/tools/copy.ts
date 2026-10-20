import crypto from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { HostStep, applyParams, rolloutParams, runSteps } from '../core/plan.js';
import { q } from '../core/ssh.js';
import { run, writeTools } from './helpers.js';
import { targetParam } from './fleet.js';

const MAX_BYTES = 12 * 1024 * 1024;

/** One line per path: kind, size, sha256 (files) or content hash of the tree (dirs), or "missing". */
export const MANIFEST = `for p in "$@"; do
  if [ -f "$p" ]; then printf 'F\\t%s\\t%s\\t%s\\n' "$p" "$(stat -c %s "$p")" "$(sha256sum "$p" | cut -c1-16)"
  elif [ -d "$p" ]; then printf 'D\\t%s\\t%s\\t%s\\n' "$p" "$(find "$p" -type f | wc -l)" "$(cd "$p" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum | sha256sum | cut -c1-16)"
  else printf 'M\\t%s\\t-\\t-\\n' "$p"; fi
done`;

export interface ManifestRow {
    kind: 'file' | 'dir' | 'missing';
    path: string;
    size?: number;
    files?: number;
    sha?: string;
}

export function parseManifest(out: string): ManifestRow[] {
    return out
        .split('\n')
        .filter((l) => /^[FDM]\t/.test(l))
        .map((l) => {
            const [k, path, n, sha] = l.split('\t');
            if (k === 'M') return { kind: 'missing', path };
            return k === 'F' ? { kind: 'file', path, size: Number(n), sha } : { kind: 'dir', path, files: Number(n), sha };
        });
}

/** KEY=value lines of an env-style file set to new values (added when absent). */
export function setEnvLines(text: string, set: Record<string, string>): string {
    let out = text;
    for (const [k, v] of Object.entries(set)) {
        const re = new RegExp(`^(export\\s+)?${k}=.*$`, 'm');
        out = re.test(out) ? out.replace(re, (_m, ex: string | undefined) => `${ex ?? ''}${k}=${v}`) : `${out.replace(/\n?$/, '\n')}${k}=${v}\n`;
    }
    return out;
}

export function registerCopyTools(server: McpServer, ctx: Ctx) {
    writeTools(() => {
        server.tool(
            'host_copy',
            'Copy files or directories from one host to others through this machine (certificates, /opt/remnanode/docker-compose.yml with the node key, /etc/log-upload/secrets.env, haproxy.cfg …): what the owner did by hand when moving an ingress or cloning a node. Contents are never shown: the plan lists size and sha256 on the source and on each target. Existing target paths are archived to /root/mia-backup-<time>.tgz first. For one env-style file, `set` changes KEY=value lines on the way (e.g. LOG_NODE_NAME).',
            {
                from: z.string().describe('source host (inventory)'),
                target: z.string().min(1).describe(`destination hosts: ${targetParam.description ?? ''}`),
                paths: z.array(z.string().regex(/^\/[\w@%+=:,./-]+$/, 'absolute path')).min(1),
                set: z.record(z.string().regex(/^[A-Z_][A-Z0-9_]*$/), z.string()).optional().describe('only with one file: KEY=value lines to set'),
                mode: z.string().regex(/^[0-7]{3,4}$/).optional().describe('chmod for copied files, e.g. 600'),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'host_copy', args, { ...args, defaultBatch: 1 }, async () => {
                        const inv = ctx.inventory();
                        const src = inv.get(args.from);
                        const targets = inv.resolve(args.target).filter((h) => h.name !== src.name);
                        if (args.set && args.paths.length !== 1) throw new Error('set works on exactly one file');
                        const man = await ctx.transport.exec(src, `set -- ${args.paths.map(q).join(' ')}\n${MANIFEST}`, { timeoutMs: 60_000 });
                        if (!man.ok) throw new Error(`${src.name}: ${man.error}`);
                        const source = parseManifest(man.stdout);
                        const missing = source.filter((r) => r.kind === 'missing').map((r) => r.path);
                        const blockers = missing.length ? [`missing on ${src.name}: ${missing.join(', ')}`] : [];
                        if (args.set && source[0]?.kind !== 'file') blockers.push('set needs a regular file');

                        let payload = '';
                        let unpack = '';
                        if (!blockers.length) {
                            if (args.set) {
                                const r = await ctx.transport.exec(src, `base64 -w0 < ${q(args.paths[0])}`, { timeoutMs: 60_000 });
                                if (!r.ok) throw new Error(`${src.name}: ${r.error}`);
                                const text = setEnvLines(Buffer.from(r.stdout.trim(), 'base64').toString('utf8'), args.set);
                                payload = Buffer.from(text).toString('base64');
                                unpack = `mkdir -p ${q(args.paths[0].replace(/\/[^/]*$/, '') || '/')}\nbase64 -d > ${q(args.paths[0])}.mia-new <<'MIA_B64'\n${payload.replace(/(.{76})/g, '$1\n')}\nMIA_B64\nmv -f ${q(args.paths[0])}.mia-new ${q(args.paths[0])}`;
                            } else {
                                const rel = args.paths.map((p) => p.replace(/^\/+/, ''));
                                const r = await ctx.transport.exec(src, `tar -C / -czf - ${rel.map(q).join(' ')} | base64 -w0`, { timeoutMs: 300_000 });
                                if (!r.ok) throw new Error(`${src.name}: tar: ${r.error}`);
                                payload = r.stdout.trim();
                                unpack = `base64 -d <<'MIA_B64' | tar -C / -xzpf -\n${payload.replace(/(.{76})/g, '$1\n')}\nMIA_B64`;
                            }
                            if (payload.length * 0.75 > MAX_BYTES) blockers.push(`too big to copy through this machine (${Math.round((payload.length * 0.75) / 1e6)} MB > 12 MB)`);
                        }
                        const payloadHash = crypto.createHash('sha256').update(payload).digest('hex').slice(0, 16);
                        const files = args.paths.filter((_, i) => source[i]?.kind === 'file');

                        return Promise.all(
                            targets.map(async (h): Promise<HostStep> => {
                                const cur = await ctx.transport.exec(h, `set -- ${args.paths.map(q).join(' ')}\n${MANIFEST}`, { timeoutMs: 60_000 });
                                if (!cur.ok) return { host: h, action: '-', script: '', blockers: [`unreachable: ${cur.error}`] };
                                const now = parseManifest(cur.stdout);
                                const existing = now.filter((r) => r.kind !== 'missing').map((r) => r.path.replace(/^\/+/, ''));
                                const same = !args.set && now.every((r, i) => r.kind === source[i]?.kind && r.sha === source[i]?.sha);
                                return {
                                    host: h,
                                    action: `copy ${args.paths.join(' ')} from ${src.name}${args.set ? ` (set ${Object.keys(args.set).join(', ')})` : ''}${args.mode ? ` mode ${args.mode}` : ''}`,
                                    noop: same && !args.mode ? 'already identical' : undefined,
                                    script: [
                                        'set -eo pipefail',
                                        'b=/root/mia-backup-$(date +%Y%m%d-%H%M%S).tgz',
                                        existing.length ? `tar -C / -czf "$b" ${existing.map(q).join(' ')} && chmod 600 "$b" && echo "backup $b"` : 'echo "nothing to back up"',
                                        unpack,
                                        ...(args.mode ? files.map((f) => `chmod ${args.mode} ${q(f)}`) : []),
                                        `set -- ${args.paths.map(q).join(' ')}`,
                                        MANIFEST,
                                    ].join('\n'),
                                    timeoutMs: 300_000,
                                    preview: { source, target: now },
                                    fingerprint: [payloadHash, now],
                                    blockers: blockers.length ? blockers : undefined,
                                    verify: async (res) => {
                                        const after = parseManifest(res.stdout);
                                        if (args.set) return after[0]?.kind === 'file' ? true : 'file not written';
                                        const bad = after.filter((r, i) => r.sha !== source[i]?.sha).map((r) => r.path);
                                        return bad.length ? `differs from the source after copy: ${bad.join(', ')}` : true;
                                    },
                                };
                            }),
                        );
                    }),
                ),
        );
    });
}
