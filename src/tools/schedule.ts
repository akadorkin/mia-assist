import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { report } from '../core/progress.js';
import { SCHEDULE_SCRIPT, parseSchedule, sortJobs, ScheduledJob } from '../core/schedule.js';
import { pool } from '../core/ssh.js';
import { HostStep, applyParams, rolloutParams, runSteps } from '../core/plan.js';
import { script } from '../core/scripts.js';
import { run, writeTools } from './helpers.js';
import { targetParam } from './fleet.js';

export function registerScheduleTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'fleet_schedule',
        'Everything that runs on a schedule, Cronicle-style: systemd timers and cron jobs on every host — schedule, last run (when, result, duration), next run, failures first. cron does not log results, so for cron only the last start (journal/syslog) is known. Stock OS jobs (apt-daily, fstrim, logrotate …) are hidden unless all=true or they fail.',
        {
            target: targetParam,
            all: z.boolean().default(false).describe('show stock OS jobs too (apt-daily, fstrim, logrotate …)'),
            failedOnly: z.boolean().default(false).describe('only failed / never-run jobs'),
        },
        ({ target, all, failedOnly }) =>
            run(async () => {
                const hosts = ctx.inventory().resolve(target);
                report({ kind: 'hosts', phase: 'probe', hosts: hosts.map((h) => h.name) });
                const res = await pool(hosts, ctx.config.concurrency, async (h) => {
                    report({ kind: 'host', host: h.name, state: 'run' });
                    const t0 = Date.now();
                    const r = await ctx.transport.exec(h, SCHEDULE_SCRIPT, { timeoutMs: 60_000 });
                    report({ kind: 'host', host: h.name, state: r.ok ? 'ok' : 'fail', note: r.ok ? undefined : r.error, ms: Date.now() - t0 });
                    return r;
                });
                const unreachable: Record<string, string> = {};
                let jobs: ScheduledJob[] = [];
                for (const r of res) {
                    if (!r.ok) {
                        unreachable[r.host] = String(r.error ?? 'no answer').split(' — ')[0];
                        continue;
                    }
                    jobs.push(...parseSchedule(r.host, r.stdout));
                }
                const total = jobs.length;
                jobs = jobs.filter((j) => all || !j.system || j.state === 'failed');
                if (failedOnly) jobs = jobs.filter((j) => j.state === 'failed' || j.state === 'never');
                sortJobs(jobs);
                return {
                    summary: {
                        hosts: hosts.length,
                        jobs: jobs.length,
                        hidden: total - jobs.length,
                        failed: jobs.filter((j) => j.state === 'failed').length,
                        running: jobs.filter((j) => j.state === 'running').length,
                        never: jobs.filter((j) => j.state === 'never').length,
                        unreachable: Object.keys(unreachable).length,
                    },
                    unreachable,
                    jobs,
                };
            }),
    );

    writeTools(() => {
        server.tool(
            'schedule_toggle',
            'Switch a scheduled job off / on, or run a timer now (the «Расписание» buttons): a systemd timer — disable --now / enable --now (+ reset-failed of its service), run = start its service; a cron job — the exact line in /etc/crontab, /etc/cron.d/* or a user crontab is commented out with «#mia-off » (enable removes the marker; a copy of the file goes to /root/mia-backup first). Reversible.',
            {
                host: z.string().describe('inventory host'),
                action: z.enum(['disable', 'enable', 'run']).describe('disable / enable, or run a timer now'),
                unit: z.string().regex(/^[\w@.-]+\.timer$/, 'a .timer unit').optional().describe('the timer (for timers)'),
                cronFile: z.string().regex(/^(\/etc\/crontab|\/etc\/cron\.d\/[\w.\-]+)$/, '/etc/crontab or /etc/cron.d/<file>').optional().describe('cron: the file with the line'),
                cronUser: z.string().regex(/^[\w.\-]+$/).optional().describe('cron: whose crontab (instead of a file)'),
                cronLine: z.string().max(2000).optional().describe('cron: the exact line (as fleet_schedule shows it)'),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'schedule_toggle', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const timer = !!args.unit;
                        if (!timer && !(args.cronLine && (args.cronFile || args.cronUser))) throw new Error('нужен unit (таймер) или cronLine + cronFile/cronUser (cron)');
                        if (!timer && args.action === 'run') throw new Error('«запустить сейчас» — только для таймеров');
                        const service = timer ? args.unit!.replace(/\.timer$/, '.service') : '';
                        const env: Record<string, string> = timer
                            ? { UNIT: args.unit!, SERVICE: service, ACTION: args.action }
                            : { LINE: args.cronLine!, FILE: args.cronFile ?? '', CU: args.cronUser ?? '', ACTION: args.action };
                        // the current state, for the dry run and the planHash
                        const look = timer
                            ? 'printf "%s %s\\n" "$(systemctl is-enabled "$UNIT" 2>/dev/null || true)" "$(systemctl is-active "$UNIT" 2>/dev/null || true)"'
                            : [
                                  'if [ -n "$CU" ]; then crontab -l -u "$CU" 2>/dev/null; else cat "$FILE" 2>/dev/null; fi > /tmp/.mia-cron.$$ || true',
                                  'if grep -qxF -- "$LINE" /tmp/.mia-cron.$$; then echo on; elif grep -qxF -- "#mia-off $LINE" /tmp/.mia-cron.$$; then echo off; else echo missing; fi',
                                  'rm -f /tmp/.mia-cron.$$',
                              ].join('\n');
                        const cur = await ctx.transport.exec(h, look, { env, timeoutMs: 30_000 });
                        if (!cur.ok) return [{ host: h, action: args.action, script: '', blockers: [`unreachable: ${cur.error}`] }];
                        const now = cur.stdout.trim();
                        const step: HostStep = {
                            host: h,
                            action: timer
                                ? args.action === 'run' ? `systemctl start ${service}` : `systemctl ${args.action} --now ${args.unit}`
                                : `${args.action === 'disable' ? 'закомментировать' : 'раскомментировать'} строку в ${args.cronUser ? `crontab -u ${args.cronUser}` : args.cronFile}`,
                            env,
                            preview: timer ? { timer: args.unit, now } : { line: args.cronLine, where: args.cronUser ? `crontab -u ${args.cronUser}` : args.cronFile, now },
                            fingerprint: now,
                            timeoutMs: 60_000,
                            script: timer
                                ? [
                                      'set -e',
                                      'case "$ACTION" in',
                                      '  disable) systemctl disable --now "$UNIT"; systemctl reset-failed "$SERVICE" 2>/dev/null || true ;;',
                                      '  enable) systemctl reset-failed "$SERVICE" 2>/dev/null || true; systemctl enable --now "$UNIT" ;;',
                                      '  run) systemctl reset-failed "$SERVICE" 2>/dev/null || true; systemctl start --no-block "$SERVICE" ;;',
                                      'esac',
                                      'echo "state=$(systemctl is-enabled "$UNIT" 2>/dev/null || true)/$(systemctl is-active "$UNIT" 2>/dev/null || true) service=$(systemctl is-active "$SERVICE" 2>/dev/null || true)"',
                                  ].join('\n')
                                : [
                                      'set -e',
                                      'T=$(mktemp)',
                                      'if [ -n "$CU" ]; then crontab -l -u "$CU" > "$T"; else cp -a "$FILE" "$T"; fi',
                                      'mkdir -p /root/mia-backup && cp -a "$T" "/root/mia-backup/$(echo "${CU:-$FILE}" | tr / _).$(date +%Y%m%d-%H%M%S)"',
                                      // exact line match, python keeps everything else byte for byte
                                      "python3 - \"$T\" <<'PY'",
                                      'import os, sys',
                                      'p = sys.argv[1]; line = os.environ["LINE"]; act = os.environ["ACTION"]',
                                      'src, dst = (line, "#mia-off " + line) if act == "disable" else ("#mia-off " + line, line)',
                                      'rows = open(p).read().split("\\n"); n = 0',
                                      'for i, r in enumerate(rows):',
                                      '    if r.rstrip() == src: rows[i] = dst; n += 1',
                                      'if not n: sys.exit("строка не найдена: " + src)',
                                      'open(p, "w").write("\\n".join(rows)); print("changed=%d" % n)',
                                      'PY',
                                      'if [ -n "$CU" ]; then crontab -u "$CU" "$T"; else cat "$T" > "$FILE"; fi',
                                      'rm -f "$T"',
                                  ].join('\n'),
                            verify: async (res) => (timer ? /state=/.test(res.stdout) || `нет состояния: ${res.stdout.trim()}` : /changed=\d+/.test(res.stdout) || `не изменилось: ${res.stdout.trim()}`),
                        };
                        if (now === 'missing') step.blockers = ['строки нет ни включённой, ни выключенной (#mia-off) — список задач устарел, обновите «Расписание»'];
                        else if (timer && args.action === 'disable' && /^disabled /.test(now) && !/ active$/.test(now)) step.noop = 'таймер уже выключен';
                        else if (timer && args.action === 'enable' && /^enabled active$/.test(now)) step.noop = 'таймер уже включён';
                        else if (!timer && args.action === 'disable' && now === 'off') step.noop = 'строка уже выключена';
                        else if (!timer && args.action === 'enable' && now === 'on') step.noop = 'строка уже включена';
                        return [step];
                    }),
                ),
        );
    });

    writeTools(() => {
        server.tool(
            'cron_logging',
            'Make every cron job write its output to a log and rotate those logs. A line that already appends to a file keeps it and the file joins rotation unless another logrotate config covers it; output to /dev/null or nowhere → >> /var/log/cron/<job>.log 2>&1; a pipe into logger stays in syslog. Rotation: /etc/logrotate.d/cron-jobs (weekly, 8 copies, compress, copytruncate). Every line also runs through /usr/local/sbin/mia-cronrun, which records start, end and exit code so fleet_schedule shows a result for cron jobs (the command itself is unchanged). Stock OS cron files are left alone; copies of touched files go to /root/mia-backup; a logrotate error after the change rolls the rotation file back. Roll out a few hosts at a time and look at fleet_schedule in between.',
            { target: targetParam, ...rolloutParams, ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'cron_logging', args, { ...args, defaultBatch: 5 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const py = script('cron-logging.py');
                        const run = (mode: string) => `MODE=${mode} python3 - <<'MIAPY'\n${py}\nMIAPY`;
                        const res = await pool(hosts, ctx.config.concurrency, (h) => ctx.transport.exec(h, run('plan'), { timeoutMs: 60_000 }));
                        return hosts.map((h, i): HostStep => {
                            const r = res[i];
                            if (!r.ok) return { host: h, action: 'cron_logging', script: '', blockers: [`unreachable: ${r.error}`] };
                            let p: { change: Array<{ where: string; before: string; after: string; log: string }>; keep: unknown[]; skipped: unknown[]; wrapper?: { install: boolean }; rotation: { new: string[]; add: string[]; rewrite: boolean } };
                            try {
                                p = JSON.parse(r.stdout.trim().split('\n').pop() ?? '{}');
                            } catch {
                                return { host: h, action: 'cron_logging', script: '', blockers: [`разбор не удался: ${r.stdout.slice(-200)} ${r.stderr.slice(-200)}`] };
                            }
                            const step: HostStep = {
                                host: h,
                                action: `${p.change.length} ${p.change.length === 1 ? 'строка' : 'строк'} cron → лог и отметка итога${p.wrapper?.install ? ' (ставлю mia-cronrun)' : ''}, ротация ${p.rotation.new.length + p.rotation.add.length} файлов`,
                                script: run('apply'),
                                preview: {
                                    change: p.change.map((c) => `${c.where}: ${c.after}`),
                                    keep: p.keep.length,
                                    rotationAdd: [...p.rotation.new, ...p.rotation.add],
                                    skipped: p.skipped,
                                },
                                fingerprint: [p.change, p.rotation, p.wrapper],
                                timeoutMs: 120_000,
                                verify: async (out) => {
                                    try {
                                        const d = JSON.parse(out.stdout.trim().split('\n').pop() ?? '{}');
                                        if (d.rolledBack) return `logrotate не принял ротацию, файл возвращён: ${(d.logrotateErrors ?? []).join('; ')}`;
                                        if ((d.logrotateErrors ?? []).length) return `ошибки logrotate: ${d.logrotateErrors.join('; ')}`;
                                        if (d.wrapperCheck && d.wrapperCheck !== 'ok') return `mia-cronrun не работает: ${d.wrapperCheck}`;
                                        return true;
                                    } catch {
                                        return `непонятный ответ: ${out.stdout.slice(-200)}`;
                                    }
                                },
                            };
                            if (!p.change.length && !p.rotation.rewrite && !p.wrapper?.install) step.noop = 'все задачи уже пишут в лог и отметку итога, ротация на месте';
                            return step;
                        });
                    }),
                ),
        );
    });
}
