/**
 * «Расписание» — what runs on a schedule on every host, Cronicle-style: systemd timers and cron jobs with
 * the schedule, the last run (when, result, how long) and the next one. One bash pass per host (SCHEDULE_SCRIPT),
 * parsed here. cron itself does not log results: jobs wrapped by cron_logging (/usr/local/sbin/mia-cronrun) leave
 * start / end / exit code in /var/lib/mia-cron/<id>.json; for the others only «when it last started» is known.
 */

export interface ScheduledJob {
    host: string;
    kind: 'timer' | 'cron';
    /** timer unit / «file: user» for cron */
    name: string;
    /** what runs: the service for a timer, the command line for cron */
    runs: string;
    description?: string;
    /** OnCalendar / OnUnitActiveSec… for timers, the 5 fields (or @daily) for cron */
    schedule: string;
    user?: string;
    /** unix seconds */
    last?: number;
    next?: number;
    /** timers: success / exit-code / timeout / signal … (systemd Result); cron: success / exit-code when wrapped by mia-cronrun */
    result?: string;
    exitStatus?: number;
    durationSec?: number;
    /** running now (timers) */
    running?: boolean;
    state: 'failed' | 'running' | 'ok' | 'never' | 'unknown' | 'off';
    /** cron: the exact line in its file / crontab (schedule_toggle finds it by this) */
    line?: string;
    /** cron: crontab of this user instead of a file */
    crontabUser?: string;
    /** stock OS jobs (apt-daily, fstrim, logrotate …) — hidden unless all=true or they fail */
    system: boolean;
}

/** Bash run on each host (sudo). Lines: N now tz | T timer props service props | C file line | U user line | R ts user cmd | S syslog line. */
export const SCHEDULE_SCRIPT = String.raw`
export LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_PAGER=
printf 'N\t%s\t%s\n' "$(date +%s)" "$(date +%z)"
systemctl list-units --type=timer --all --plain --no-legend 2>/dev/null | awk '{print $1}' | grep '\.timer$' | while read -r t; do
  p=$(systemctl show "$t" -p Unit -p TimersCalendar -p TimersMonotonic -p ActiveState 2>/dev/null | tr '\n' '\037')
  # systemd prints these in the host's local time whatever --timestamp says: drop weekday and zone, let date(1) read it
  nx=$(systemctl show "$t" -p NextElapseUSecRealtime --value 2>/dev/null | awk 'NF>=3{print $2" "$3}')
  lt=$(systemctl show "$t" -p LastTriggerUSec --value 2>/dev/null | awk 'NF>=3{print $2" "$3}')
  p="$p""NEXT_TS=$( [ -n "$nx" ] && date -d "$nx" +%s 2>/dev/null )"$'\037'"LAST_TS=$( [ -n "$lt" ] && date -d "$lt" +%s 2>/dev/null )"$'\037'
  u=$(printf '%s' "$p" | tr '\037' '\n' | sed -n 's/^Unit=//p')
  s=$(systemctl show "$u" --timestamp=unix -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp -p ActiveState -p Description -p ExecStart 2>/dev/null | tr '\n' '\037')
  printf 'T\t%s\t%s\t%s\n' "$t" "$p" "$s"
done
for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] || continue
  grep -vE '^\s*(#|$)|^\s*[A-Za-z_][A-Za-z0-9_]*\s*=' "$f" 2>/dev/null | while IFS= read -r l; do printf 'C\t%s\t%s\n' "$f" "$l"; done
done
for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] || continue
  grep -E '^#mia-off ' "$f" 2>/dev/null | sed 's/^#mia-off //' | while IFS= read -r l; do printf 'D\t%s\t%s\n' "$f" "$l"; done
done
for u in root $(ls /var/spool/cron/crontabs 2>/dev/null); do
  crontab -l -u "$u" 2>/dev/null | grep -E '^#mia-off ' | sed 's/^#mia-off //' | while IFS= read -r l; do printf 'E\t%s\t%s\n' "$u" "$l"; done
done | sort -u
for u in root $(ls /var/spool/cron/crontabs 2>/dev/null); do
  crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)|^\s*[A-Za-z_][A-Za-z0-9_]*\s*=' | while IFS= read -r l; do printf 'U\t%s\t%s\n' "$u" "$l"; done
done | sort -u
journalctl -t CRON --since "-3 days" -o short-unix --no-pager 2>/dev/null | grep -F ') CMD (' | tail -n 3000 | sed -E 's/^([0-9]+)\.[0-9]+ \S+ CRON\[[0-9]+\]: \(([^)]*)\) CMD \((.*)\)$/R\t\1\t\2\t\3/' | grep '^R'
grep -hF ') CMD (' /var/log/syslog /var/log/cron.log 2>/dev/null | grep 'CRON\[' | tail -n 3000 | sed 's/^/S\t/'
for f in /var/lib/mia-cron/*.json; do [ -f "$f" ] && printf 'K\t%s\t%s\n' "$(basename "$f" .json)" "$(tr -d '\n' < "$f")"; done
true  # no marks yet (glob unmatched) must not turn the whole host into «unreachable»
`;

const SYSTEM_TIMER = /^(prometheus-node-exporter-[\w-]+|apt-daily(-upgrade)?|fstrim|logrotate|man-db|motd-news|e2scrub_all|dpkg-db-backup|sysstat-(collect|summary|rotate)|update-notifier-[\w-]+|fwupd-refresh|snapd\.[\w.-]+|systemd-[\w-]+|apport-autoreport|ua-timer|ua-reboot-cmds|esm-cache|xfs_scrub_all|plocate-updatedb|mdcheck_[\w]+|mdmonitor-oneshot|anacron|phpsessionclean|launchpadlib-cache-clean|update-notifier|snapper-[\w-]+|btrfs-[\w-]+|logwatch|mlocate|pg_[\w-]+)\.timer$/;
const SYSTEM_CRON_FILE = /\/(e2scrub_all|popularity-contest|sysstat|php|\.placeholder|anacron|mdadm|zfsutils-linux)$/;

/** key=value lines joined by \x1f; a key systemd repeats (one TimersMonotonic line per rule) is concatenated */
const kv = (s: string) => {
    const o: Record<string, string> = {};
    for (const l of s.split('\x1f').filter(Boolean)) {
        const k = l.slice(0, l.indexOf('='));
        const v = l.slice(l.indexOf('=') + 1);
        o[k] = o[k] ? `${o[k]} ${v}` : v;
    }
    return o;
};
/** "15min", "1h 30min", "2d", "45s" → seconds */
export function spanSec(v: string): number | undefined {
    let t = 0;
    let any = false;
    for (const m of v.matchAll(/(\d+(?:\.\d+)?)\s*(us|ms|s|sec|min|m|h|d|w)\b/g)) {
        any = true;
        const n = Number(m[1]);
        t += m[2] === 'w' ? n * 604800 : m[2] === 'd' ? n * 86400 : m[2] === 'h' ? n * 3600 : m[2] === 'min' || m[2] === 'm' ? n * 60 : m[2] === 'ms' || m[2] === 'us' ? 0 : n;
    }
    return any ? Math.round(t) : undefined;
}
const MONO_RU: Record<string, string> = { OnBootUSec: 'после загрузки', OnStartupUSec: 'после старта systemd', OnActiveUSec: 'после включения', OnUnitActiveUSec: 'каждые', OnUnitInactiveUSec: 'через … после окончания' };
/** systemd --timestamp=unix: "@1790000000" (or "0"/"" when never) → seconds */
const unixTs = (v?: string) => {
    const m = v?.match(/^@(\d+)/);
    return m && Number(m[1]) > 0 ? Number(m[1]) : undefined;
};

/** "{ OnCalendar=*-*-* 03:10:00 ; next_elapse=… }" → "*-*-* 03:10:00"; monotonic → "каждые 30min" */
function timerSchedule(cal: string, mono: string): string {
    const parts: string[] = [];
    for (const m of cal.matchAll(/OnCalendar=([^;}]+?)\s*;/g)) parts.push(m[1].trim());
    for (const m of mono.matchAll(/(On\w+USec)=([^;}]+?)\s*;/g)) {
        const ru = MONO_RU[m[1]] ?? m[1];
        parts.push(ru.includes('…') ? ru.replace('…', m[2].trim()) : `${ru} ${m[2].trim()}`);
    }
    return parts.join(' · ') || '—';
}

const CRON_MACRO: Record<string, string> = { '@hourly': '0 * * * *', '@daily': '0 0 * * *', '@midnight': '0 0 * * *', '@weekly': '0 0 * * 0', '@monthly': '0 0 1 * *', '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *' };

/** One cron field → the set of allowed values. */
function field(spec: string, min: number, max: number): Set<number> | undefined {
    const out = new Set<number>();
    for (const part of spec.split(',')) {
        const m = part.match(/^(\*|\d+(?:-\d+)?)(?:\/(\d+))?$/);
        if (!m) return undefined;
        const step = m[2] ? Number(m[2]) : 1;
        let a = min;
        let b = max;
        if (m[1] !== '*') {
            const [x, y] = m[1].split('-').map(Number);
            a = x;
            b = y ?? (m[2] ? max : x);
        }
        for (let v = a; v <= b; v += step) out.add(v === 7 && max === 7 ? 0 : v);
    }
    return out;
}

/** Next start of a 5-field cron expression after `from` (unix s), in a fixed UTC offset (minutes). */
export function cronNext(expr: string, from: number, offsetMin: number): number | undefined {
    const e = CRON_MACRO[expr] ?? expr;
    const f = e.trim().split(/\s+/);
    if (f.length !== 5) return undefined;
    const [mi, ho, dm, mo, dw] = [field(f[0], 0, 59), field(f[1], 0, 23), field(f[2], 1, 31), field(f[3], 1, 12), field(f[4], 0, 7)];
    if (!mi || !ho || !dm || !mo || !dw) return undefined;
    const domAny = f[2] === '*';
    const dowAny = f[4] === '*';
    let t = Math.floor(from / 60) * 60 + 60;
    for (let i = 0; i < 60 * 24 * 370; i++, t += 60) {
        const d = new Date((t + offsetMin * 60) * 1000);
        if (!mi.has(d.getUTCMinutes()) || !ho.has(d.getUTCHours()) || !mo.has(d.getUTCMonth() + 1)) continue;
        const okDom = dm.has(d.getUTCDate());
        const okDow = dw.has(d.getUTCDay());
        // classic cron: when both day fields are restricted, either matching is enough
        if (domAny || dowAny ? okDom && okDow : okDom || okDow) return t;
    }
    return undefined;
}

/** "+0300" → 180 */
const tzMin = (z?: string) => {
    const m = z?.match(/^([+-])(\d{2})(\d{2})$/);
    return m ? (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) : 0;
};

interface CronLine {
    file: string;
    user: string;
    schedule: string;
    command: string;
    line?: string;
    crontabUser?: string;
    off?: boolean;
}

function parseCronLine(file: string, line: string, user?: string): CronLine | undefined {
    const s = line.trim();
    // /etc/crontab and /etc/cron.d carry a user column; personal crontabs do not
    const withUser = !user;
    let m = s.match(/^(@\w+)\s+(.*)$/);
    if (m) {
        const rest = m[2].trim();
        if (withUser) {
            const u = rest.match(/^(\S+)\s+(.*)$/);
            if (!u) return undefined;
            return { file, user: u[1], schedule: m[1], command: u[2] };
        }
        return { file, user: user!, schedule: m[1], command: rest };
    }
    m = s.match(withUser ? /^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(\S+)\s+(.*)$/ : /^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.*)$/);
    if (!m) return undefined;
    return withUser ? { file, user: m[2], schedule: m[1], command: m[3] } : { file, user: user!, schedule: m[1], command: m[2] };
}

const WRAPPED = /^\/usr\/local\/sbin\/mia-cronrun\s+(\S+)\s+'((?:[^']|'\\'')*)'(?:\s+(%.*))?$/s;
/** A cron command wrapped by cron_logging → its id and the command as it was written. */
export function unwrapCron(cmd: string): { id?: string; command: string } {
    const m = cmd.trim().match(WRAPPED);
    if (!m) return { command: cmd };
    return { id: m[1], command: m[2].replace(/'\\''/g, "'") + (m[3] ? ` ${m[3]}` : '') };
}

/** Parse SCHEDULE_SCRIPT output of one host. */
export function parseSchedule(host: string, out: string): ScheduledJob[] {
    let now = Math.floor(Date.now() / 1000);
    let offset = 0;
    const jobs: ScheduledJob[] = [];
    const cron: CronLine[] = [];
    const runs = new Map<string, number>(); // command → last start
    const marks = new Map<string, { start?: number; end?: number; rc?: number }>(); // mia-cronrun id → last run
    const seen = (cmd: string, ts: number) => {
        const k = cmd.trim();
        if ((runs.get(k) ?? 0) < ts) runs.set(k, ts);
    };
    for (const line of out.split('\n')) {
        const [tag, ...rest] = line.split('\t');
        if (tag === 'N') {
            now = Number(rest[0]) || now;
            offset = tzMin(rest[1]);
        } else if (tag === 'T' && rest.length >= 3) {
            const [unit, tp, sp] = rest;
            const t = kv(tp);
            const s = kv(sp);
            const start = unixTs(s.ExecMainStartTimestamp);
            const exit = unixTs(s.ExecMainExitTimestamp);
            const last = (Number(t.LAST_TS) || undefined) ?? start;
            // interval timers have no wall-clock next elapse: last start (+ run time for OnUnitInactive) + interval
            let next = Number(t.NEXT_TS) || undefined;
            if (!next && last) {
                const ua = t.TimersMonotonic?.match(/OnUnitActiveUSec=([^;}]+?)\s*;/);
                const ui = t.TimersMonotonic?.match(/OnUnitInactiveUSec=([^;}]+?)\s*;/);
                if (ua) next = last + (spanSec(ua[1]) ?? 0) || undefined;
                else if (ui) next = (exit && start && exit >= start ? exit : last) + (spanSec(ui[1]) ?? 0) || undefined;
            }
            const running = s.ActiveState === 'activating' || (s.ActiveState === 'active' && !!start && (!exit || exit < start));
            const result = s.Result || undefined;
            const failed = s.ActiveState === 'failed' || (!!result && result !== 'success');
            const cmd = s.ExecStart?.match(/path=([^ ;]+)/)?.[1];
            jobs.push({
                host,
                kind: 'timer',
                name: unit,
                runs: t.Unit ? `${t.Unit}${cmd ? ` (${cmd})` : ''}` : unit,
                description: s.Description || undefined,
                schedule: timerSchedule(t.TimersCalendar ?? '', t.TimersMonotonic ?? ''),
                last,
                next,
                result,
                exitStatus: s.ExecMainStatus !== undefined && s.ExecMainStatus !== '' ? Number(s.ExecMainStatus) : undefined,
                durationSec: start && exit && exit >= start ? exit - start : undefined,
                running,
                // a timer that is not enabled (shipped by a package, switched off) is not a failure to look at
                state: failed ? 'failed' : running ? 'running' : t.ActiveState !== 'active' ? (last ? 'off' : 'unknown') : last ? 'ok' : 'never',
                // a stock timer, or one shipped by a package and never switched on, is noise; one that ran and was switched off is not
                system: (SYSTEM_TIMER.test(unit) || (t.ActiveState !== 'active' && !last)) && !failed,
            });
        } else if ((tag === 'C' || tag === 'D') && rest.length >= 2) {
            const c = parseCronLine(rest[0], rest.slice(1).join('\t'));
            if (c) cron.push({ ...c, line: rest.slice(1).join('\t'), off: tag === 'D' });
        } else if ((tag === 'U' || tag === 'E') && rest.length >= 2) {
            const c = parseCronLine(`crontab -u ${rest[0]}`, rest.slice(1).join('\t'), rest[0]);
            if (c) cron.push({ ...c, line: rest.slice(1).join('\t'), crontabUser: rest[0], off: tag === 'E' });
        } else if (tag === 'K' && rest.length >= 2) {
            try {
                marks.set(rest[0], JSON.parse(rest.slice(1).join('\t')));
            } catch {
                /* a half-written mark: skip */
            }
        } else if (tag === 'R' && rest.length >= 3) {
            seen(rest.slice(2).join('\t'), Number(rest[0]));
        } else if (tag === 'S') {
            const m = rest.join('\t').match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s.*CRON\[\d+\]: \(([^)]*)\) CMD \((.*)\)$/);
            if (m) {
                const ts = Math.floor(Date.parse(m[1]) / 1000);
                if (Number.isFinite(ts)) seen(m[3], ts);
            }
        }
    }
    for (const c of cron) {
        // the stock /etc/crontab run-parts lines are just the cron.hourly/daily/… dispatch
        const system = SYSTEM_CRON_FILE.test(c.file) || (c.file === '/etc/crontab' && /run-parts|anacron|cron\.(hourly|daily|weekly|monthly)/.test(c.command));
        const w = unwrapCron(c.command);
        const mark = w.id ? marks.get(w.id) : undefined;
        const started = runs.get(c.command.trim());
        const last = Math.max(started ?? 0, mark?.start ?? 0) || undefined;
        const ended = mark?.end !== undefined && mark.start !== undefined;
        // a mark without an end is a run in progress — unless it is a day old (the host went down mid-run)
        const running = !!mark?.start && !ended && now - mark.start < 86_400;
        const result = ended ? (mark!.rc === 0 ? 'success' : 'exit-code') : undefined;
        jobs.push({
            host,
            kind: 'cron',
            name: `${c.file}${c.user ? ` · ${c.user}` : ''}`,
            runs: w.command,
            schedule: c.schedule,
            user: c.user,
            last,
            next: c.off ? undefined : cronNext(c.schedule, now, offset),
            result,
            exitStatus: ended ? mark!.rc : undefined,
            durationSec: ended ? Math.max(0, mark!.end! - mark!.start!) : undefined,
            running: running || undefined,
            state: c.off ? 'off' : result === 'exit-code' ? 'failed' : running ? 'running' : result ? 'ok' : c.schedule === '@reboot' ? 'unknown' : last ? 'ok' : 'unknown',
            system: system && !c.off,
            line: c.line,
            crontabUser: c.crontabUser,
        });
    }
    return jobs;
}

const ORDER: Record<ScheduledJob['state'], number> = { failed: 0, running: 1, never: 2, off: 3, unknown: 4, ok: 5 };
export function sortJobs(jobs: ScheduledJob[]): ScheduledJob[] {
    return jobs.sort((a, b) => ORDER[a.state] - ORDER[b.state] || a.host.localeCompare(b.host) || (a.next ?? Infinity) - (b.next ?? Infinity));
}
