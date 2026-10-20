import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSchedule, unwrapCron } from '../src/core/schedule.js';

test('unwrapCron gives back the command as it was written', () => {
    assert.deepEqual(unwrapCron(`/usr/local/sbin/mia-cronrun user-root-ab12cd 'echo it'\\''s >> /var/log/x.log 2>&1'`), {
        id: 'user-root-ab12cd',
        command: "echo it's >> /var/log/x.log 2>&1",
    });
    assert.deepEqual(unwrapCron(`/usr/local/sbin/mia-cronrun j1 'cat > /tmp/a' %hello`), { id: 'j1', command: 'cat > /tmp/a %hello' });
    assert.deepEqual(unwrapCron('/usr/bin/true'), { command: '/usr/bin/true' });
});

test('cron jobs wrapped by mia-cronrun get a result, a duration and a state', () => {
    const now = 1_791_550_000;
    const out = [
        `N\t${now}\t+0300`,
        `U\troot\t*/5 * * * * /usr/local/sbin/mia-cronrun ok-1 '/opt/a.sh >> /var/log/a.log 2>&1'`,
        `U\troot\t0 3 * * * /usr/local/sbin/mia-cronrun bad-1 '/opt/b.sh >> /var/log/b.log 2>&1'`,
        `U\troot\t* * * * * /usr/local/sbin/mia-cronrun run-1 '/opt/c.sh'`,
        `U\troot\t0 4 * * * /opt/plain.sh`,
        `K\tok-1\t{"start":${now - 120},"end":${now - 100},"rc":0,"user":"root"}`,
        `K\tbad-1\t{"start":${now - 4000},"end":${now - 3990},"rc":2,"user":"root"}`,
        `K\trun-1\t{"start":${now - 30},"pid":42,"user":"root"}`,
    ].join('\n');
    const jobs = parseSchedule('h', out);
    const by = (cmd: string) => jobs.find((j) => j.runs.startsWith(cmd))!;
    assert.equal(by('/opt/a.sh').state, 'ok');
    assert.equal(by('/opt/a.sh').result, 'success');
    assert.equal(by('/opt/a.sh').durationSec, 20);
    assert.equal(by('/opt/a.sh').last, now - 120);
    assert.equal(by('/opt/b.sh').state, 'failed');
    assert.equal(by('/opt/b.sh').exitStatus, 2);
    assert.equal(by('/opt/c.sh').state, 'running');
    assert.equal(by('/opt/plain.sh').result, undefined);
    // the exact line stays wrapped: schedule_toggle finds it by this
    assert.match(by('/opt/a.sh').line!, /mia-cronrun ok-1/);
});

test('the schedule script ends with success even when a host has no marks yet', async () => {
    const { SCHEDULE_SCRIPT } = await import('../src/core/schedule.js');
    assert.match(SCHEDULE_SCRIPT.trim().split('\n').pop()!, /^true\b/);
});
