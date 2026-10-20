import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cronNext, parseSchedule, spanSec } from '../src/core/schedule.js';

const at = (iso: string) => Math.floor(Date.parse(iso) / 1000);

test('cron next start: fields, steps, ranges, macros, day-of-month OR day-of-week, host offset', () => {
    const msk = 180;
    // 2026-10-01 18:47 MSK = 15:47Z
    const now = at('2026-10-01T15:47:00Z');
    assert.equal(cronNext('*/5 * * * *', now, msk), at('2026-10-01T15:50:00Z'));
    assert.equal(cronNext('15 4-17 * * *', now, msk), at('2026-10-02T01:15:00Z'), '04:15 MSK tomorrow');
    assert.equal(cronNext('20 4 1 * *', now, msk), at('2026-11-01T01:20:00Z'), 'first of the month');
    assert.equal(cronNext('@daily', now, msk), at('2026-10-01T21:00:00Z'), 'midnight MSK');
    assert.equal(cronNext('0 */2 * * *', now, msk), at('2026-10-01T17:00:00Z'), '20:00 MSK');
    assert.equal(cronNext('0 9 13 * 5', now, msk), at('2026-10-02T06:00:00Z'), 'Fridays OR the 13th: Friday 2 Oct');
    assert.equal(cronNext('bad', now, msk), undefined);
    assert.equal(spanSec('1h 30min'), 5400);
    assert.equal(spanSec('15min'), 900);
});

test('schedule parse: timers with result and duration, interval next, cron last start from the journal, stock jobs marked', () => {
    const now = at('2026-10-01T15:47:00Z');
    const S = '\x1f';
    const out = [
        `N\t${now}\t+0300`,
        `T\tjf-translate.timer\tUnit=jf-translate.service${S}TimersCalendar={ OnCalendar=*-*-* 06:50:00 ; next_elapse=@1 }${S}TimersMonotonic=${S}ActiveState=active${S}NEXT_TS=${now + 3600}${S}LAST_TS=${now - 7200}${S}` +
            `\tResult=exit-code${S}ExecMainStatus=1${S}ExecMainStartTimestamp=@${now - 7200}${S}ExecMainExitTimestamp=@${now - 6843}${S}ActiveState=failed${S}Description=Ночная доводка${S}`,
        `T\tfleet-textfile.timer\tUnit=fleet-textfile.service${S}TimersCalendar=${S}TimersMonotonic={ OnUnitActiveUSec=2min ; next_elapse=x }${S}TimersMonotonic={ OnBootUSec=1min ; next_elapse=y }${S}ActiveState=active${S}NEXT_TS=${S}LAST_TS=${now - 30}${S}` +
            `\tResult=success${S}ExecMainStatus=0${S}ExecMainStartTimestamp=@${now - 30}${S}ExecMainExitTimestamp=@${now - 29}${S}ActiveState=inactive${S}`,
        `T\tlogrotate.timer\tUnit=logrotate.service${S}TimersCalendar={ OnCalendar=daily ; }${S}ActiveState=active${S}NEXT_TS=${now + 100}${S}LAST_TS=${now - 100}${S}\tResult=success${S}ActiveState=inactive${S}`,
        `C\t/etc/cron.d/ufw-blacklist\t0 */2 * * * root /usr/local/bin/ufw-blacklist.sh >> /var/log/ufw_blacklist_cron.log 2>&1`,
        `C\t/etc/crontab\t17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly`,
        `U\tops\t*/10 * * * * /home/ops/bin/sync.sh`,
        `R\t${now - 2700}\troot\t/usr/local/bin/ufw-blacklist.sh >> /var/log/ufw_blacklist_cron.log 2>&1`,
        `S\t2026-10-01T18:40:01.123+03:00 node CRON[123]: (ops) CMD (/home/ops/bin/sync.sh)`,
    ].join('\n');
    const jobs = parseSchedule('ingress1', out);
    const jf = jobs.find((j) => j.name === 'jf-translate.timer')!;
    assert.equal(jf.state, 'failed');
    assert.equal(jf.durationSec, 357);
    assert.equal(jf.exitStatus, 1);
    assert.equal(jf.next, now + 3600);
    const ft = jobs.find((j) => j.name === 'fleet-textfile.timer')!;
    assert.equal(ft.schedule, 'каждые 2min · после загрузки 1min', 'every TimersMonotonic line, in words');
    assert.equal(ft.next, now - 30 + 120, 'interval timers: last + interval');
    assert.equal(jobs.find((j) => j.name === 'logrotate.timer')!.system, true);
    const off = parseSchedule('fi1', `N\t${now}\t+0300\nT\tprom-ipmi.timer\tUnit=prom-ipmi.service${S}ActiveState=inactive${S}\tResult=success${S}ActiveState=inactive${S}`)[0];
    assert.equal(off.state, 'unknown', 'a disabled timer never ran — not «never»');
    assert.equal(off.system, true, 'and is hidden with the stock jobs');
    const ufw = jobs.find((j) => j.runs.startsWith('/usr/local/bin/ufw-blacklist.sh'))!;
    assert.equal(ufw.user, 'root');
    assert.equal(ufw.last, now - 2700, 'last start from the journal');
    assert.equal(ufw.next, at('2026-10-01T17:00:00Z'));
    assert.equal(jobs.find((j) => j.runs.includes('run-parts'))!.system, true, 'the stock cron.hourly dispatch');
    const own = jobs.find((j) => j.runs === '/home/ops/bin/sync.sh')!;
    assert.equal(own.name, 'crontab -u ops · ops');
    assert.equal(own.last, at('2026-10-01T15:40:01Z'), 'or from syslog');
});
