import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { Document, parseDocument } from 'yaml';
import { z } from 'zod';
import { registry } from '../tools/helpers.js';
import { Ctx } from './ctx.js';
import { redact, redactText } from './output.js';
import { PanelCallResult, parseJson, unspill } from './remnawave.js';
import { hashOf } from './plan.js';
import { shq } from './ssh.js';

/** What the engine needs from the panel side (RemnawaveBridge, or a fake in tests). */
export interface PanelBridge {
    call(name: string, args: Record<string, unknown>): Promise<PanelCallResult>;
}

/**
 * Scenarios: ordered, resumable runbooks made of steps that each need the owner's yes.
 *   check     read-only tool call (mia or panel); passes on its own when `expect` holds
 *   mia       a mia write tool: dry run → planHash → apply
 *   panel     an mcp-remnawave tool: plan/apply (planHash), confirmName, or a direct call
 *   manual    something only the owner can do (DNS, provider console, CI button) → "done"
 *   inventory an edit of the local fleet.yaml (comments kept, backup written)
 *   local     commands on this machine (git in the owner's repo checkouts), shown before they run
 * Nothing is applied without a decision; the state is saved after every step.
 */

export type StepKind = 'check' | 'mia' | 'panel' | 'manual' | 'inventory' | 'local';
export type Decision = 'apply' | 'done' | 'skip' | 'retry';

export interface RunVars {
    params: Record<string, any>;
    /** Values saved by earlier steps (uuids, addresses, lists …). */
    vars: Record<string, any>;
}

export interface StepDef {
    id: string;
    title: string;
    kind: StepKind;
    /** Tool name: a mia tool (check/mia) or an mcp-remnawave tool (check with panel:true, panel). */
    tool?: string;
    /** For `check`: call the panel instead of mia. */
    panel?: boolean;
    /** For `check` without a tool: a local read-only check (DNS, a local file …). */
    run?: (ctx: Ctx, r: RunVars) => Promise<unknown>;
    /** For `check`: keep re-checking up to timeoutSec before asking (a job finishing, a node connecting). */
    poll?: { timeoutSec: number; everySec?: number; settled?: (data: any) => boolean };
    /** For `local`: files to write in the owner's repo checkouts (preview: diff against `base` or the current file). */
    files?: (r: RunVars, ctx: Ctx) => Array<{ path: string; content: string; base?: string }>;
    /** For `local`: commands to run after the files, in order (no shell; argv as given). */
    commands?: (r: RunVars, ctx: Ctx) => Array<{ cwd: string; argv: string[] }>;
    args?: (r: RunVars) => Record<string, unknown>;
    /** Panel write protocol: plan (apply+planHash, default), confirmName (destructive), direct (writes on call). */
    protocol?: 'plan' | 'confirmName' | 'direct';
    /** confirmName value for the confirmName protocol. */
    confirm?: (r: RunVars) => string;
    /** manual: what the owner has to do. */
    instruction?: (r: RunVars) => string;
    /** inventory: change the parsed fleet.yaml, return a one-line summary. */
    edit?: (doc: Document, r: RunVars) => string;
    /** Result check (check steps: pass/fail; write steps: verification after apply). true = fine. */
    expect?: (data: any, r: RunVars) => string | true;
    /** Keep something from the result for later steps. */
    save?: (data: any, r: RunVars) => void;
    /** Step only applies when this holds (else skipped as n/a). */
    when?: (r: RunVars) => boolean;
    /** Check that must pass (RU reachability): if the owner skips it while it fails, only the steps with
     *  onGateFail = this id run after it (the rollback), the rest are n/a and the run ends (AUD-16). */
    gate?: boolean;
    /** Runs only when the gate with this id failed and was skipped (rollback). */
    onGateFail?: string;
}

export interface ScenarioDef {
    name: string;
    title: string;
    description: string;
    params: z.ZodRawShape;
    /** Steps may depend on vars saved by earlier steps (e.g. one step per profile found), never on later ones. */
    steps: (params: Record<string, any>, vars: Record<string, any>) => StepDef[];
}

export interface StepLog {
    id: string;
    status: 'applied' | 'passed' | 'done' | 'skipped' | 'n/a' | 'failed';
    at: string;
    summary?: string;
}

export interface RunState {
    id: string;
    scenario: string;
    params: Record<string, any>;
    vars: Record<string, any>;
    index: number;
    log: StepLog[];
    pending?: { stepId: string; planHash?: string; confirm?: string; preview?: unknown };
    createdAt: string;
    updatedAt: string;
    finished?: boolean;
}

export interface StepView {
    run: string;
    scenario: string;
    n: number;
    total: number;
    id: string;
    title: string;
    kind: StepKind;
    /** What the owner can answer now. */
    choices: Decision[];
    /** mia / panel steps: the tool the step calls (the console asks more for irreversible ones). */
    tool?: string;
    preview?: unknown;
    problem?: string;
}

export interface Advance {
    /** Steps that passed on their own (checks) or were skipped as n/a on the way. */
    passed: Array<{ id: string; title: string; status: string; summary?: string }>;
    /** The step waiting for a decision, or none when finished. */
    step?: StepView;
    /** Outcome of the decision just taken. */
    outcome?: { id: string; status: string; summary?: string; result?: unknown };
    finished?: boolean;
    log?: StepLog[];
}

export class ScenarioEngine {
    private dir: string;

    constructor(
        private ctx: Ctx,
        private scenarios: Map<string, ScenarioDef>,
        private bridge?: PanelBridge,
        /** Multiplies every poll timeout of check steps (0 in tests: check once). */
        private pollScale = 1,
    ) {
        this.dir = path.join(ctx.config.stateDir, 'scenarios');
    }

    list() {
        return [...this.scenarios.values()].map((s) => ({
            name: s.name,
            title: s.title,
            description: s.description,
            params: Object.entries(s.params).map(([k, t]) => {
                const zt = t as z.ZodTypeAny;
                const def = zt instanceof z.ZodDefault ? (zt._def.defaultValue as () => unknown)() : undefined;
                return { name: k, required: !zt.isOptional(), about: zt.description ?? '', ...(def !== undefined ? { default: def } : {}) };
            }),
        }));
    }

    runs() {
        if (!fs.existsSync(this.dir)) return [];
        return fs
            .readdirSync(this.dir)
            .filter((f) => f.endsWith('.json'))
            .map((f) => JSON.parse(fs.readFileSync(path.join(this.dir, f), 'utf8')) as RunState)
            .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
            .map((r) => ({ run: r.id, scenario: r.scenario, step: `${Math.min(r.index + 1, this.steps(r).length)}/${this.steps(r).length}`, finished: !!r.finished, updatedAt: r.updatedAt }));
    }

    private def(name: string): ScenarioDef {
        const s = this.scenarios.get(name);
        if (!s) throw new Error(`нет ранбука «${name}»; есть: ${[...this.scenarios.keys()].join(', ')}`);
        return s;
    }

    private steps(r: RunState): StepDef[] {
        return this.def(r.scenario).steps(r.params, r.vars);
    }

    private save(r: RunState) {
        fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
        r.updatedAt = new Date().toISOString();
        fs.writeFileSync(path.join(this.dir, `${r.id}.json`), JSON.stringify(redact(r), null, 1), { mode: 0o600 });
    }

    load(id: string): RunState {
        const f = path.join(this.dir, `${id}.json`);
        if (!fs.existsSync(f)) throw new Error(`нет прогона ${id} (список: mia scenario runs)`);
        return JSON.parse(fs.readFileSync(f, 'utf8'));
    }

    async start(name: string, rawParams: Record<string, unknown>): Promise<Advance> {
        const def = this.def(name);
        const parsed = z.object(def.params).strict().safeParse(rawParams);
        if (!parsed.success) throw new Error(`${name}: ${parsed.error.issues.map((i) => `${i.path.join('.') || 'параметры'}: ${i.message}`).join('; ')}`);
        def.steps(parsed.data, {}); // parameter errors surface now, not halfway through
        const now = new Date().toISOString();
        const r: RunState = {
            id: `${name}-${now.replace(/[-:]/g, '').slice(0, 13)}-${crypto.randomBytes(2).toString('hex')}`,
            scenario: name,
            params: parsed.data,
            vars: {},
            index: 0,
            log: [],
            createdAt: now,
            updatedAt: now,
        };
        this.save(r);
        return this.prepare(r);
    }

    async resume(id: string): Promise<Advance> {
        return this.prepare(this.load(id));
    }

    /** Move to the next step that needs a decision: run passing checks, skip n/a steps, build the preview. */
    private async prepare(r: RunState, passed: Advance['passed'] = []): Promise<Advance> {
        const rv: RunVars = { params: r.params, vars: r.vars };
        let steps = this.steps(r);
        // steps may depend on vars saved by the step before: rebuild the list every time
        for (; r.index < (steps = this.steps(r)).length; ) {
            const s = steps[r.index];
            if ((r.vars.gateFailed ? s.onGateFail !== r.vars.gateFailed : !!s.onGateFail) || (s.when && !s.when(rv))) {
                this.logStep(r, s, 'n/a');
                passed.push({ id: s.id, title: s.title, status: 'n/a' });
                r.index++;
                continue;
            }
            const view: StepView = { run: r.id, scenario: r.scenario, n: r.index + 1, total: steps.length, id: s.id, title: s.title, kind: s.kind, choices: [], ...(s.tool ? { tool: s.tool } : {}) };
            try {
                if (s.kind === 'check') {
                    const until = Date.now() + (s.poll?.timeoutSec ?? 0) * 1000 * this.pollScale;
                    let res: { ok: boolean; data: unknown; text: string };
                    let verdict: string | true;
                    for (;;) {
                        res = s.run ? await s.run(this.ctx, rv).then((data) => ({ ok: true, data, text: '' })) : await this.callTool(s, s.args?.(rv) ?? {}, !!s.panel);
                        verdict = !res.ok ? res.text : s.expect ? s.expect(res.data, rv) : true;
                        if (verdict === true || Date.now() >= until || (res.ok && s.poll?.settled?.(res.data))) break;
                        await new Promise((ok) => setTimeout(ok, (s.poll?.everySec ?? 15) * 1000));
                    }
                    if (verdict === true) {
                        s.save?.(res.data, rv);
                        const summary = short(res.data);
                        this.logStep(r, s, 'passed', summary);
                        passed.push({ id: s.id, title: s.title, status: 'passed', summary });
                        r.index++;
                        continue;
                    }
                    view.problem = verdict;
                    view.preview = res.data;
                    view.choices = ['retry', 'skip'];
                } else if (s.kind === 'manual') {
                    view.preview = s.instruction?.(rv);
                    view.choices = ['done', 'skip'];
                    r.pending = { stepId: s.id };
                } else if (s.kind === 'inventory') {
                    const { before, after, summary } = this.inventoryEdit(s, rv, false);
                    view.preview = { summary, diff: lineDiff(before, after), file: this.ctx.config.inventoryFile };
                    view.choices = ['apply', 'skip'];
                    r.pending = { stepId: s.id, planHash: this.shownHash(s, rv) };
                } else if (s.kind === 'local') {
                    const files = s.files?.(rv, this.ctx) ?? [];
                    const cmds = s.commands?.(rv, this.ctx) ?? [];
                    view.preview = {
                        ...(files.length
                            ? {
                                  files: files.map((f) => {
                                      const cur = fs.existsSync(f.path) ? fs.readFileSync(f.path, 'utf8') : undefined;
                                      const against = f.base ?? cur ?? '';
                                      return { path: f.path, status: cur === undefined ? 'new' : cur === f.content ? 'unchanged' : 'changed', [f.base !== undefined ? 'diffFromTemplate' : 'diff']: lineDiff(against, f.content) };
                                  }),
                              }
                            : {}),
                        ...(cmds.length ? { run: cmds.map((c) => `(cd ${c.cwd} && ${c.argv.map(shq).join(' ')})`) } : {}),
                    };
                    view.choices = ['apply', 'skip'];
                    r.pending = { stepId: s.id, planHash: this.shownHash(s, rv) };
                } else if (s.kind === 'mia') {
                    const res = await this.callTool(s, { ...(s.args?.(rv) ?? {}), apply: false }, false);
                    if (!res.ok) throw new Error(res.text);
                    const d = res.data as { mode?: string; planHash?: string; toRun?: number; blocked?: string[] };
                    if (d.toRun === 0 && !d.blocked?.length) {
                        // already in the wanted state on every host: nothing to confirm
                        this.logStep(r, s, 'passed', 'уже сделано, менять нечего');
                        passed.push({ id: s.id, title: s.title, status: 'passed', summary: 'уже сделано, менять нечего' });
                        r.index++;
                        continue;
                    }
                    view.preview = res.data;
                    r.pending = { stepId: s.id, planHash: d.planHash, preview: res.data };
                    if (d.blocked?.length) {
                        view.problem = `блокеры: ${d.blocked.join('; ')}`;
                        view.choices = ['retry', 'skip'];
                    } else view.choices = ['apply', 'skip'];
                } else if (s.kind === 'panel') {
                    const args = s.args?.(rv) ?? {};
                    const protocol = s.protocol ?? 'plan';
                    if (protocol === 'direct') {
                        view.preview = { call: s.tool, args };
                        r.pending = { stepId: s.id };
                    } else {
                        const res = await this.callTool(s, protocol === 'plan' ? { ...args, apply: false } : args, true);
                        if (!res.ok) throw new Error(res.text);
                        const d = res.data as { planHash?: string; blocked?: string[]; changed?: number };
                        if (protocol === 'plan' && d.changed === 0 && !d.blocked?.length) {
                            this.logStep(r, s, 'passed', 'в панели уже так, менять нечего');
                            passed.push({ id: s.id, title: s.title, status: 'passed', summary: 'в панели уже так, менять нечего' });
                            r.index++;
                            continue;
                        }
                        view.preview = res.data;
                        r.pending = { stepId: s.id, planHash: d.planHash, confirm: s.confirm?.(rv), preview: res.data };
                        if (d.blocked?.length) view.problem = `блокеры: ${d.blocked.join('; ')}`;
                    }
                    view.choices = view.problem ? ['retry', 'skip'] : ['apply', 'skip'];
                }
            } catch (e) {
                view.problem = e instanceof Error ? e.message : String(e);
                view.choices = ['retry', 'skip'];
            }
            this.save(r);
            return { passed, step: view };
        }
        r.finished = true;
        r.pending = undefined;
        this.save(r);
        return { passed, finished: true, log: r.log };
    }

    /** Change parameters of a run in flight (e.g. new SNIs a step asked for), then re-check the current step. */
    async setParams(id: string, patch: Record<string, unknown>): Promise<Advance> {
        const r = this.load(id);
        const def = this.def(r.scenario);
        const parsed = z.object(def.params).strict().safeParse({ ...r.params, ...patch });
        if (!parsed.success) throw new Error(parsed.error.issues.map((i) => `${i.path.join('.') || 'параметры'}: ${i.message}`).join('; '));
        def.steps(parsed.data, r.vars);
        r.params = parsed.data;
        r.pending = undefined;
        this.save(r);
        return this.prepare(r);
    }

    /** Take the owner's decision on the current step, then prepare the next one. */
    async decide(id: string, decision: Decision): Promise<Advance> {
        const r = this.load(id);
        if (r.finished) return { passed: [], finished: true, log: r.log };
        const steps = this.steps(r);
        const s = steps[r.index];
        const rv: RunVars = { params: r.params, vars: r.vars };
        if (decision === 'retry') return this.prepare(r);
        if (decision === 'skip') {
            if (s.gate) r.vars.gateFailed = s.id; // ворота пропускают только проваленными: дальше лишь откат (AUD-16)
            this.logStep(r, s, 'skipped');
            r.index++;
            r.pending = undefined;
            const next = await this.prepare(r);
            return { ...next, outcome: { id: s.id, status: 'skipped' } };
        }
        if (s.kind === 'manual') {
            if (decision !== 'done') throw new Error(`шаг «${s.id}» делается руками: ответ «сделано» или «пропустить»`);
            this.logStep(r, s, 'done');
            r.index++;
            r.pending = undefined;
            const next = await this.prepare(r);
            return { ...next, outcome: { id: s.id, status: 'done' } };
        }
        if (decision !== 'apply') throw new Error(`шаг «${s.id}»: ответ apply, «пропустить» или «проверить снова»`);
        this.ctx.assertWritable();
        if (!r.pending || r.pending.stepId !== s.id) return this.prepare(r);
        // fleet.yaml or the files changed while the owner read the diff: show the new one instead of applying it unseen
        if ((s.kind === 'inventory' || s.kind === 'local') && r.pending.planHash !== this.shownHash(s, rv)) return this.prepare(r);

        let result: unknown;
        let ok = true;
        let summary = '';
        if (s.kind === 'inventory') {
            summary = this.inventoryEdit(s, rv, true).summary;
            result = { summary };
        } else if (s.kind === 'local') {
            const outputs: string[] = [];
            for (const f of s.files?.(rv, this.ctx) ?? []) {
                fs.mkdirSync(path.dirname(f.path), { recursive: true });
                fs.writeFileSync(f.path, f.content);
                outputs.push(`wrote ${f.path}`);
            }
            for (const c of s.commands?.(rv, this.ctx) ?? []) {
                const res = await runLocal(c.cwd, c.argv);
                outputs.push(`$ ${c.argv.map(shq).join(' ')}\n${res.out}`.trimEnd());
                if (!res.ok) {
                    ok = false;
                    summary = `${c.argv.join(' ')}: ${res.out.split('\n').slice(-3).join(' ')}`;
                    break;
                }
            }
            result = outputs.join('\n').slice(-4000);
            if (ok) summary = 'ok';
        } else if (s.kind === 'mia' || s.kind === 'panel') {
            const args = s.args?.(rv) ?? {};
            const protocol = s.kind === 'mia' ? 'plan' : (s.protocol ?? 'plan');
            const callArgs =
                protocol === 'plan' ? { ...args, apply: true, planHash: r.pending.planHash } : protocol === 'confirmName' ? { ...args, confirmName: r.pending.confirm } : args;
            const res = await this.callTool(s, callArgs, s.kind === 'panel');
            result = res.data;
            const mode = (res.data as { mode?: string })?.mode;
            if (!res.ok) {
                ok = false;
                summary = res.text.slice(0, 500);
            } else if (mode === 'aborted') {
                // the world changed since the preview: show the fresh plan instead of applying
                const again = await this.prepare(r);
                return { ...again, outcome: { id: s.id, status: 'replanned', summary: (res.data as { reason?: string }).reason } };
            } else if (mode && !['applied', 'nothing-to-do', 'nothing-to-change'].includes(mode)) {
                ok = false;
                summary = `результат: ${mode}`;
            }
            if (ok && s.expect) {
                const v = s.expect(res.data, rv);
                if (v !== true) {
                    ok = false;
                    summary = `проверка после выполнения: ${v}`;
                }
            }
            if (ok) {
                s.save?.(res.data, rv);
                summary ||= mode ?? 'ok';
            }
        }
        this.ctx.state.log({ tool: `scenario:${r.scenario}`, host: String(r.params.host ?? r.params.name ?? r.params.node ?? '-'), action: `${s.id}: ${s.title}`, ok, result: summary });
        if (!ok) {
            this.logStep(r, s, 'failed', summary);
            this.save(r);
            return {
                passed: [],
                outcome: { id: s.id, status: 'failed', summary, result },
                step: { run: r.id, scenario: r.scenario, n: r.index + 1, total: steps.length, id: s.id, title: s.title, kind: s.kind, choices: ['retry', 'skip'], problem: summary, preview: result },
            };
        }
        this.logStep(r, s, 'applied', summary);
        r.index++;
        r.pending = undefined;
        this.save(r); // before prepare(): its waits can take minutes, a restart then must not offer the applied step again
        const next = await this.prepare(r);
        return { ...next, outcome: { id: s.id, status: 'applied', summary, result } };
    }

    private logStep(r: RunState, s: StepDef, status: StepLog['status'], summary?: string) {
        r.log.push({ id: s.id, status, at: new Date().toISOString(), ...(summary ? { summary: summary.slice(0, 300) } : {}) });
    }

    private async callTool(s: StepDef, args: Record<string, unknown>, panel: boolean): Promise<{ ok: boolean; data: unknown; text: string }> {
        if (!s.tool) throw new Error(`у шага ${s.id} нет инструмента`);
        if (panel) {
            if (!this.bridge) throw new Error('шагам в панели нужен mcp-remnawave: задайте MIA_REMNAWAVE_MCP="node /путь/к/mcp-remnawave/dist/index.js" (и REMNAWAVE_BASE_URL/REMNAWAVE_API_TOKEN)');
            return this.bridge.call(s.tool, args);
        }
        const t = registry.get(s.tool);
        if (!t) throw new Error(`инструмент ${s.tool} недоступен${this.ctx.config.readonly ? ' (режим только чтения, MIA_READONLY=true)' : ''}`);
        const parsed = z.object(t.schema as z.ZodRawShape).strict().safeParse(args);
        if (!parsed.success) throw new Error(`${s.tool}: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
        const res = await t.handler(parsed.data);
        const text = res.content.map((c) => c.text).join('\n');
        return { ok: !res.isError, data: unspill(parseJson(text)), text };
    }

    /** Hash of what an inventory / local step shows: the diff, the files with what is on disk now, the commands. */
    private shownHash(s: StepDef, rv: RunVars): string {
        if (s.kind === 'inventory') {
            const { before, after } = this.inventoryEdit(s, rv, false);
            return hashOf([before, after]);
        }
        const files = (s.files?.(rv, this.ctx) ?? []).map((f) => [f.path, f.content, fs.existsSync(f.path) ? fs.readFileSync(f.path, 'utf8') : null]);
        return hashOf([files, s.commands?.(rv, this.ctx) ?? []]);
    }

    private inventoryEdit(s: StepDef, rv: RunVars, write: boolean): { before: string; after: string; summary: string } {
        const file = this.ctx.config.inventoryFile;
        const before = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : 'hosts: {}\n';
        const doc = parseDocument(before);
        const summary = s.edit!(doc, rv);
        const after = preserveLayout(before, doc.toString({ lineWidth: 0, flowCollectionPadding: false }));
        if (write && after !== before) {
            // backup into the state dir: fleet.yaml usually lives in a git checkout
            if (fs.existsSync(file)) {
                const dir = path.join(this.ctx.config.stateDir, 'backups');
                fs.mkdirSync(dir, { recursive: true });
                fs.copyFileSync(file, path.join(dir, `${path.basename(file)}.${new Date().toISOString().replace(/[:.]/g, '-')}`));
            }
            fs.mkdirSync(path.dirname(file), { recursive: true });
            fs.writeFileSync(file, after);
            this.ctx.inventory(); // reload, validates the result
        }
        return { before, after, summary };
    }
}

function runLocal(cwd: string, argv: string[]): Promise<{ ok: boolean; out: string }> {
    return new Promise((resolve) => {
        execFile(argv[0], argv.slice(1), { cwd, timeout: 600_000, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
            resolve({ ok: !err, out: redactText(`${stdout}${stderr}${err && !stderr ? err.message : ''}`).slice(-8000) });
        });
    });
}

function short(v: unknown): string {
    const s = typeof v === 'string' ? v : JSON.stringify(v);
    return s.length > 200 ? s.slice(0, 200) + '…' : s;
}

/** Longest common subsequence of two line lists under a key; returns matched index pairs. */
function lcs(a: string[], b: string[], key: (s: string) => string): Array<[number, number]> {
    const ka = a.map(key);
    const kb = b.map(key);
    const n = a.length;
    const m = b.length;
    const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = ka[i] === kb[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const pairs: Array<[number, number]> = [];
    for (let i = 0, j = 0; i < n && j < m; ) {
        if (ka[i] === kb[j]) pairs.push([i++, j++]);
        else if (dp[i + 1][j] >= dp[i][j + 1]) i++;
        else j++;
    }
    return pairs;
}

const layoutKey = (l: string) => l.replace(/\s+/g, ' ').replace(/([[{]) /g, '$1').replace(/ ([\]}])/g, '$1').trim();

/**
 * The yaml library re-serialises the whole file (flow padding, comment spacing, quoting).
 * Keep the owner's formatting: every line that only differs in layout stays as it was.
 */
export function preserveLayout(before: string, after: string): string {
    const a = before.split('\n');
    const b = after.split('\n');
    const out = [...b];
    const pairs = lcs(a, b, layoutKey);
    for (const [i, j] of pairs) out[j] = a[i];
    // a changed line keeps the column of its trailing comment (aligned "# …" blocks stay aligned)
    let i = 0;
    let j = 0;
    const DROP = '\u0000drop';
    for (const [pi, pj] of [...pairs, [a.length, b.length] as [number, number]]) {
        // the yaml library moves «key:   # comment» of a nested map onto its own line: put it back
        for (let k = j; k + 1 < pj; k++) {
            const key = b[k].match(/^\s*[^#\s][^#]*:\s*$/);
            const note = b[k + 1].match(/^\s*(#.*)$/);
            if (!key || !note) continue;
            const old = a.slice(i, pi).find((l) => layoutKey(l) === layoutKey(`${b[k]} ${note[1]}`));
            if (!old) continue;
            out[k] = old;
            out[k + 1] = DROP;
            k++;
        }
        for (let k = j; k < pj; k++) {
            if (out[k] === DROP) continue;
            const m = b[k].match(/^(\s*[\w.-]+:)(.*?)\s+(#.*)$/);
            if (!m) continue;
            const old = a.slice(i, pi).find((l) => l.startsWith(m[1]) && l.includes(m[3]));
            const col = old?.lastIndexOf(m[3]) ?? -1;
            const code = `${m[1]}${m[2]}`;
            if (!old || col < 0) continue;
            const gap = old.slice(0, col).match(/\s*$/)![0].length;
            out[k] = col > code.length ? `${code.padEnd(col)}${m[3]}` : `${code}${' '.repeat(Math.max(1, gap))}${m[3]}`;
        }
        i = pi + 1;
        j = pj + 1;
    }
    return out.filter((l) => l !== DROP).join('\n');
}

/** Changed lines for previews: - removed, + added, with the line number in the new file. */
export function lineDiff(a: string, b: string): string[] {
    const la = a.split('\n');
    const lb = b.split('\n');
    const pairs = lcs(la, lb, (s) => s);
    const out: string[] = [];
    let i = 0;
    let j = 0;
    for (const [pi, pj] of [...pairs, [la.length, lb.length] as [number, number]]) {
        while (i < pi) out.push(`- ${la[i++]}`);
        while (j < pj) out.push(`+${String(j + 1).padStart(5)}: ${lb[j++]}`);
        i = pi + 1;
        j = pj + 1;
    }
    return out.slice(0, 120);
}
