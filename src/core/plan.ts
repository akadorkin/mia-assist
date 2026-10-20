import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { Ctx } from './ctx.js';
import { Host } from './inventory.js';
import { redactText } from './output.js';
import { report } from './progress.js';
import { ExecOptions, ExecResult } from './ssh.js';

/** What one action will do on one host. */
export interface HostStep {
    host: Host;
    /** One line: what happens, e.g. "docker compose pull && up -d remnanode". */
    action: string;
    /** Bash run on the host (through sudo when configured). */
    script: string;
    env?: Record<string, string>;
    via?: ExecOptions['via'];
    timeoutMs?: number;
    /** Current state shown in the dry run (versions, upgradable packages, users online …). */
    preview?: Record<string, unknown>;
    /** Part of the state the plan depends on; if it changes before apply, the planHash changes. */
    fingerprint?: unknown;
    warnings?: string[];
    blockers?: string[];
    /** Skip this host: nothing to do (reason). */
    noop?: string;
    /** Run after a successful step; a throw or false marks the step failed (and stops a rollout). */
    verify?: (res: ExecResult) => Promise<string | true>;
}

export const applyParams = {
    apply: z.boolean().default(false).describe('false (default) = dry run: show what will happen on which hosts and a planHash. true = run it; needs planHash'),
    planHash: z.string().optional().describe('planHash from the dry run of the very same call, good for one apply; refused if targets or their state changed since'),
};

export const rolloutParams = {
    batch: z.number().int().min(1).optional().describe('hosts at a time (rolling). Default depends on the action: 1 for disruptive ones'),
    continueOnError: z.boolean().default(false).describe('keep going after a host fails (default: stop the rollout at the first failure)'),
    skipUnreachable: z.boolean().default(false).describe('skip hosts that do not answer over ssh instead of refusing the whole plan (they show as skipped)'),
};

export function hashOf(v: unknown): string {
    return crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex').slice(0, 12);
}

const tail = (s: string, n = 25) => redactText(s.trimEnd().split('\n').slice(-n).join('\n'));

/**
 * Dry-run / apply protocol for everything that touches hosts:
 * build steps against live state → show them with a planHash → on apply rebuild,
 * insist on the same planHash, then run in batches (rolling), verify, journal each host.
 */
export async function runSteps(
    ctx: Ctx,
    tool: string,
    args: Record<string, unknown>,
    opts: { apply: boolean; planHash?: string; batch?: number; defaultBatch: number; continueOnError?: boolean; skipUnreachable?: boolean },
    build: () => Promise<HostStep[]>,
) {
    // apply смотрит на живое состояние, а не на кеш фактов (120 с) — иначе отпечаток в planHash совпадает всегда (AUD-05)
    if (opts.apply) ctx.forget();
    // a host that does not answer blocks the plan, unless asked to leave it out (one dead node must not stop a fleet-wide update)
    const steps = (await build()).map((s) =>
        opts.skipUnreachable && s.blockers?.length && s.blockers.every((b) => b.startsWith('unreachable:')) ? { ...s, blockers: undefined, noop: `не отвечает — пропущен (${s.blockers[0].replace(/^unreachable:\s*/, '').split(' — ')[0]})` } : s,
    );
    const todo = steps.filter((s) => !s.noop);
    const batch = opts.batch ?? opts.defaultBatch;
    const gated = gate(ctx, tool, args, opts, {
        key: steps.map((s) => [s.host.name, s.action, s.noop ?? null, s.fingerprint ?? null]),
        rows: steps.map((s) => ({ host: s.host.name, ...row(s), ...(s.preview ? { now: s.preview } : {}) })),
        blockers: steps.flatMap((s) => (s.blockers ?? []).map((b) => `${s.host.name}: ${b}`)),
        toRun: todo.length,
        extra: { rollout: todo.length > 1 ? { batch, stopOnFailure: !opts.continueOnError } : undefined },
        abortedReason: 'targets or their state changed since the dry run (or the arguments differ): run a new dry run and show it before applying',
    });
    if (typeof gated !== 'string') return gated;
    const planHash = gated;

    report({ kind: 'hosts', phase: 'apply', hosts: todo.map((s) => s.host.name) });
    const results: Array<Record<string, unknown>> = [];
    let stopped: string | undefined;
    for (let i = 0; i < todo.length && !stopped; i += batch) {
        const group = todo.slice(i, i + batch);
        const res = await Promise.all(group.map((s) => runStep(ctx, tool, s, planHash)));
        results.push(...res);
        const failed = res.filter((r) => !r.ok);
        if (failed.length && !opts.continueOnError) stopped = failed.map((r) => r.host).join(', ');
    }
    const done = new Set(results.map((r) => r.host));
    const notRun = todo.filter((s) => !done.has(s.host.name)).map((s) => s.host.name);
    return {
        mode: stopped ? 'stopped' : results.every((r) => r.ok) ? 'applied' : 'applied-with-errors',
        planHash,
        ...(stopped ? { stoppedAt: stopped, notRun } : {}),
        results,
    };
}

const row = (s: { action: string; noop?: string; warnings?: string[]; blockers?: string[] }) => ({
    ...(s.noop ? { skip: s.noop } : { will: s.action }),
    ...(s.warnings?.length ? { warnings: s.warnings } : {}),
    ...(s.blockers?.length ? { blockers: s.blockers } : {}),
});

/** The part runSteps and runApiSteps share: planHash, the dry-run answer, the apply checks. Returns the planHash to run with, or the answer. */
function gate(
    ctx: Ctx,
    tool: string,
    args: Record<string, unknown>,
    opts: { apply: boolean; planHash?: string },
    p: { key: unknown; rows: Array<Record<string, unknown>>; blockers: string[]; toRun: number; extra?: Record<string, unknown>; abortedReason: string },
): string | Record<string, unknown> {
    const { apply: _a, planHash: _p, ...keyArgs } = args;
    const planHash = hashOf([tool, keyArgs, p.key]);
    const blocked = p.blockers.length ? { blocked: p.blockers } : {};
    // planHash одноразовый (AUD-16): холостой прогон кладёт метку, apply её забирает — повтор или второй
    // одновременный apply того же плана получает aborted, даже из другого процесса на этой машине
    const plans = path.join(ctx.config.stateDir, 'plans');
    const mark = path.join(plans, planHash);
    if (!opts.apply) {
        if (p.toRun && !p.blockers.length) {
            fs.mkdirSync(plans, { recursive: true, mode: 0o700 });
            for (const f of fs.readdirSync(plans)) if (Date.now() - (fs.statSync(path.join(plans, f), { throwIfNoEntry: false })?.mtimeMs ?? Date.now()) > 864e5) fs.rmSync(path.join(plans, f), { force: true }); // метки старше суток — в мусор
            fs.writeFileSync(mark, '');
        }
        return {
            mode: 'dry-run',
            planHash,
            hosts: p.rows.length,
            toRun: p.toRun,
            ...p.extra,
            ...blocked,
            plan: p.rows,
            next: !p.toRun ? 'Nothing to do.' : p.blockers.length ? 'Resolve the blockers first.' : `To run: call ${tool} again with the same arguments plus apply:true, planHash:"${planHash}".`,
        };
    }
    ctx.assertWritable();
    if (!opts.planHash) throw new Error('apply needs planHash from a dry run of the same call');
    // без planHash: изменённый план сначала показывают человеку новым холостым прогоном (AUD-05)
    if (opts.planHash !== planHash) return { mode: 'aborted', reason: p.abortedReason, plan: p.rows.map(({ warnings: _w, blockers: _b, ...r }) => r) };
    if (p.blockers.length) return { mode: 'aborted', reason: 'blocked', ...blocked };
    if (!p.toRun) return { mode: 'nothing-to-do', planHash };
    try {
        fs.unlinkSync(mark);
    } catch {
        return { mode: 'aborted', reason: 'this plan was already applied (or never dry-run here): run a new dry run and show it before applying' };
    }
    return planHash;
}

/** One change made through an API (DNS record, tailnet device, runner …) rather than on a host. */
export interface ApiStep {
    /** What is changed, e.g. "cloudflare A pl3.example.com". */
    target: string;
    action: string;
    before?: unknown;
    after?: unknown;
    /** Nothing to do (reason). */
    noop?: string;
    warnings?: string[];
    blockers?: string[];
    apply: () => Promise<unknown>;
    /** After a successful apply: true or what is wrong. */
    verify?: () => Promise<string | true>;
}

/** Same dry run → planHash → apply protocol as runSteps, for API changes; one at a time, journaled per change. */
export async function runApiSteps(
    ctx: Ctx,
    tool: string,
    args: Record<string, unknown>,
    opts: { apply: boolean; planHash?: string },
    build: () => Promise<ApiStep[]>,
) {
    const steps = await build();
    const todo = steps.filter((s) => !s.noop);
    const gated = gate(ctx, tool, args, opts, {
        key: steps.map((s) => [s.target, s.action, s.noop ?? null, s.before ?? null, s.after ?? null]),
        rows: steps.map((s) => ({
            target: s.target,
            ...row(s),
            ...(s.before !== undefined ? { now: s.before } : {}),
            ...(s.after !== undefined && !s.noop ? { after: s.after } : {}),
        })),
        blockers: steps.flatMap((s) => (s.blockers ?? []).map((b) => `${s.target}: ${b}`)),
        toRun: todo.length,
        abortedReason: 'the state changed since the dry run (or the arguments differ): run a new dry run and show it before applying',
    });
    if (typeof gated !== 'string') return gated;
    const planHash = gated;
    const results: Array<Record<string, unknown>> = [];
    for (const s of todo) {
        const started = Date.now();
        try {
            const res = await s.apply();
            const v = s.verify ? await s.verify() : true;
            const ok = v === true;
            ctx.state.log({ tool, host: s.target, action: s.action, ok, result: ok ? 'ok' : `verify: ${v}`, ms: Date.now() - started, planHash });
            results.push({ target: s.target, ok, ...(ok ? {} : { error: `verify: ${v}` }), ...(res !== undefined ? { result: res } : {}) });
            if (!ok) break;
        } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            ctx.state.log({ tool, host: s.target, action: s.action, ok: false, result: msg, ms: Date.now() - started, planHash });
            results.push({ target: s.target, ok: false, error: msg });
            break;
        }
    }
    const done = new Set(results.map((r) => r.target));
    const notRun = todo.filter((s) => !done.has(s.target)).map((s) => s.target);
    return { mode: results.every((r) => r.ok) && !notRun.length ? 'applied' : 'stopped', planHash, results, ...(notRun.length ? { notRun } : {}) };
}

async function runStep(ctx: Ctx, tool: string, s: HostStep, planHash: string): Promise<Record<string, unknown> & { host: string; ok: boolean }> {
    const res = await ctx.transport.exec(s.host, s.script, { env: s.env, via: s.via, timeoutMs: s.timeoutMs });
    // the host is not what the remembered probe says any more
    ctx.forget(s.host.name);
    let ok = res.ok;
    let verified: string | undefined;
    if (ok && s.verify) {
        try {
            const v = await s.verify(res);
            if (v !== true) {
                ok = false;
                verified = v;
            } else verified = 'ok';
        } catch (e) {
            ok = false;
            verified = e instanceof Error ? e.message : String(e);
        }
    }
    const summary = ok ? 'ok' : (verified && verified !== 'ok' ? `verify: ${verified}` : res.error) ?? 'failed';
    ctx.state.log({ tool, host: s.host.name, action: s.action, ok, result: summary, ms: res.ms, planHash });
    return {
        host: s.host.name,
        ok,
        ms: res.ms,
        ...(verified ? { verified } : {}),
        ...(!ok ? { error: summary } : {}),
        output: tail(res.stdout),
        ...(res.stderr.trim() && !ok ? { stderr: tail(res.stderr, 15) } : {}),
    };
}

/** Wait until check() returns true or the time is up; returns the last check value. */
export async function waitFor(check: () => Promise<string | true>, timeoutMs: number, everyMs = 5000): Promise<string | true> {
    const until = Date.now() + timeoutMs;
    let last: string | true = 'not checked';
    while (Date.now() < until) {
        last = await check();
        if (last === true) return true;
        await new Promise((r) => setTimeout(r, everyMs));
    }
    return last;
}
