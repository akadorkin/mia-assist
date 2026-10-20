import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { HostStep, applyParams, rolloutParams, runSteps } from '../core/plan.js';
import { q } from '../core/ssh.js';
import { run, writeTools } from './helpers.js';
import { targetParam } from './fleet.js';


/** A file of a local repo checkout, refusing paths that leave it. */
export function repoFile(root: string, rel: string): string {
    const abs = path.resolve(root, rel);
    if (abs !== root && !abs.startsWith(root + path.sep)) throw new Error(`${rel}: outside the repo`);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) throw new Error(`${rel}: no such file in ${root}`);
    return abs;
}

/** Commit and dirty state of a checkout, for the plan (so it is clear which version runs). */
export function repoState(root: string): { commit?: string; dirty?: string[]; error?: string } {
    try {
        const commit = execFileSync('git', ['-C', root, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
        const dirty = execFileSync('git', ['-C', root, 'status', '--porcelain'], { encoding: 'utf8' })
            .split('\n')
            .filter(Boolean)
            .map((l) => l.slice(3));
        return { commit, ...(dirty.length ? { dirty: dirty.slice(0, 20) } : {}) };
    } catch (e) {
        return { error: e instanceof Error ? e.message.split('\n')[0] : String(e) };
    }
}

/** Remote bash that recreates the given repo files in a temp dir, runs the script from there, and removes the dir. */
/** A script argument: plain text (quoted), or {env} — the value of an exported variable, so a secret never shows in the plan or journal. */
export type RepoArg = string | { env: string };

export function repoRunner(files: Array<{ rel: string; body: Buffer }>, script: string, args: RepoArg[], installTo?: string, runIt = true): string {
    const lines = ['set -eo pipefail', 'd=$(mktemp -d /tmp/mia-repo.XXXXXX)', "trap 'rm -rf \"$d\"' EXIT", 'chmod 700 "$d"'];
    for (const f of files) {
        const dir = path.posix.dirname(f.rel);
        if (dir !== '.') lines.push(`mkdir -p "$d"/${q(dir)}`);
        // base64 has no quote or $ characters: safe inside a quoted heredoc
        lines.push(`base64 -d > "$d"/${q(f.rel)} <<'MIA_B64'`, f.body.toString('base64').replace(/(.{76})/g, '$1\n').trimEnd(), 'MIA_B64');
    }
    const argv = args.map((a) => ' ' + (typeof a === 'string' ? q(a) : `"$${/^[A-Z_][A-Z0-9_]*$/.test(a.env) ? a.env : 'INVALID'}"`)).join('');
    lines.push(`cd "$d"/${q(path.posix.dirname(script))}`);
    if (installTo) {
        // the fleet keeps some scripts installed (ufw-blacklist.sh runs from cron): replace that copy, keep the old one, run the new one
        lines.push(`bash -n ./${q(path.posix.basename(script))}`);
        lines.push(`if [ -f ${q(installTo)} ]; then cp -p ${q(installTo)} ${q(installTo)}.bak-$(date +%Y%m%d-%H%M%S); fi`, `install -D -m 755 ./${q(path.posix.basename(script))} ${q(installTo)}`, `echo "installed ${installTo}"`);
        // installOnly: only put the new copy in place — cron runs it on its own schedule (a full ufw-blacklist run
        // on the whole fleet at once reloads every firewall)
        if (runIt) lines.push(`bash ${q(installTo)}${argv} </dev/null 2>&1`);
    } else {
        // stdin is this very script: never let the owner's script read from it
        lines.push(`bash ./${q(path.posix.basename(script))}${argv} </dev/null 2>&1`);
    }
    return lines.join('\n');
}

const DISRUPTIVE = /\b(ufw\s+(--force\s+)?(reset|disable|enable)|iptables\s+-(F|X|P)|ipset\s+(destroy|flush)|systemctl\s+(restart|stop)\s+(ssh|sshd|tailscaled|docker)|reboot|shutdown)\b/;

export function registerRepoTools(server: McpServer, ctx: Ctx) {
    writeTools(() => {
        server.tool(
            'repo_script',
            'Run one of your own fleet scripts from a local repo checkout (MIA_REPOS, e.g. ops=~/src/ops-scripts) on hosts: deploy/migrate-blacklist.sh, lock-mgmt-ports-apply.sh, install-beszel.sh … The script (plus files listed in `with`, same relative paths) is sent over ssh, run as root from a temp dir, then removed. Exactly the checked-out version runs: the plan shows the commit, uncommitted changes and a hash of the files. Secrets go by env var name (envFrom): the value is read from mia\'s own environment and never shown.',
            {
                target: z.string().min(1).describe(targetParam.description ?? 'hosts'),
                repo: z.string().default('ops').describe('repo name from MIA_REPOS'),
                script: z.string().describe('path inside the repo, e.g. deploy/migrate-blacklist.sh'),
                args: z.array(z.string()).default([]),
                with: z.array(z.string()).default([]).describe('other repo files the script reads (relative paths are kept)'),
                env: z.record(z.string().regex(/^[A-Z_][A-Z0-9_]*$/), z.string()).optional().describe('non-secret variables'),
                envFrom: z.array(z.string().regex(/^[A-Z_][A-Z0-9_]*$/)).default([]).describe('names of variables to pass from mia\'s environment (secrets)'),
                installTo: z.string().regex(/^\/[\w./-]+$/).optional().describe('install the script at this path first (e.g. /usr/local/bin/ufw-blacklist.sh, which cron re-runs), then run that copy; the previous copy is kept as .bak-<time>'),
                installOnly: z.boolean().default(false).describe('with installTo: only install the new copy (bash -n checked), do not run it — cron picks it up'),
                timeoutSec: z.number().int().min(10).max(3600).default(600),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'repo_script', args, { ...args, defaultBatch: 1 }, async () => {
                        const root = ctx.config.repos[args.repo];
                        if (!root) throw new Error(`repo "${args.repo}" is not configured: set MIA_REPOS="${args.repo}=/path/to/checkout" (known: ${Object.keys(ctx.config.repos).join(', ') || 'none'})`);
                        const rels = [...new Set([args.script, ...args.with])].map((r) => path.relative(root, repoFile(root, r)).split(path.sep).join('/'));
                        const files = rels.map((rel) => ({ rel, body: fs.readFileSync(path.join(root, rel)) }));
                        const script = rels[0];
                        const sha = crypto.createHash('sha256');
                        for (const f of files) sha.update(f.rel).update(f.body);
                        const filesHash = sha.digest('hex').slice(0, 12);
                        const state = repoState(root);
                        const missing = args.envFrom.filter((n) => !process.env[n]);
                        const env: Record<string, string> = { ...(args.env ?? {}) };
                        for (const n of args.envFrom) env[n] = process.env[n] ?? '';
                        const text = files.map((f) => f.body.toString('utf8')).join('\n');
                        const warnings: string[] = [];
                        if (DISRUPTIVE.test(text)) warnings.push('the script touches the firewall / ssh / docker / reboots: keep batch 1 and check the first host before the rest');
                        if (state.dirty?.some((d) => rels.includes(d))) warnings.push('runs uncommitted changes of the script (see repo.dirty)');
                        const blockers = missing.length ? [`not set in mia's environment: ${missing.join(', ')}`] : undefined;
                        const hosts = ctx.inventory().resolve(args.target);
                        if (args.installOnly && !args.installTo) throw new Error('installOnly needs installTo');
                        const action = `${args.installTo ? `install ${args.repo}:${script} → ${args.installTo}${args.installOnly ? ' (not run)' : ', run it'}` : `${args.repo}:${script}`}${args.args.length ? ' ' + args.args.join(' ') : ''}`;
                        return hosts.map(
                            (h): HostStep => ({
                                host: h,
                                action,
                                script: repoRunner(files, script, args.args, args.installTo, !args.installOnly),
                                env,
                                timeoutMs: args.timeoutSec * 1000,
                                preview: { repo: { path: root, ...state }, files: rels, filesHash, env: Object.keys(args.env ?? {}), envFrom: args.envFrom },
                                fingerprint: [filesHash, Object.entries(env).map(([k, v]) => [k, crypto.createHash('sha256').update(v).digest('hex').slice(0, 8)])],
                                warnings: warnings.length ? warnings : undefined,
                                blockers,
                            }),
                        );
                    }),
                ),
        );
    });
}
