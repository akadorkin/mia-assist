import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseProbe, parseTarget, ruProbeScript, ruVerdict } from '../src/tools/ruprobe.js';

// 08.10.2026: both home ISPs failing while the datacenter passes = ТСПУ, roll back at once

test('ru_probe: targets, script binds each ISP and forces the address', () => {
    assert.deepEqual(parseTarget('1.2.3.4'), { ip: '1.2.3.4', port: 443, sni: '1.2.3.4' });
    assert.deepEqual(parseTarget('1.2.3.4:9443/ads.example.org'), { ip: '1.2.3.4', port: 9443, sni: 'ads.example.org' });
    assert.throws(() => parseTarget('bad target;rm'));
    const s = ruProbeScript([parseTarget('1.2.3.4/site.example.org')], ['wan0', 'wan1']);
    assert.match(s, /--interface \$w/);
    assert.match(s, /--resolve "\$sni:\$port:\$ip"/);
    assert.match(s, /1\.2\.3\.4 443 site\.example\.org/);
});

test('ru_probe: verdicts', () => {
    const home = parseProbe(['P|a:443/x|wan0|0|200 0.01 0.05', 'P|a:443/x|wan1|0|200 0.02 0.06', 'P|b:443/x|wan0|28| 000 0.01 0', 'P|b:443/x|wan1|35|000 0.02 0', 'P|c:443/x|wan0|0|200 0.01 0.03', 'P|c:443/x|wan1|7|000 0 0'].join('\n'));
    const dc = parseProbe('P|b:443/x|direct|0|200 0.01 0.02').map((r) => ({ ...r, via: 'dc-1' }));
    const v = ruVerdict(home, dc, { wan0: 'ISP-A', wan1: 'ISP-B' });
    assert.equal(v['a:443/x'].verdict, 'ok');
    assert.equal(v['b:443/x'].verdict, 'blocked-ru');
    assert.match(v['b:443/x'].note, /откат DNS/);
    assert.equal(v['c:443/x'].verdict, 'partial');
    assert.match(v['c:443/x'].note, /ISP-B/);
    assert.equal(ruVerdict(parseProbe('P|d:1/x|wan0|7|000 0 0'), parseProbe('P|d:1/x|direct|7|000 0 0'))['d:1/x'].verdict, 'down');
});

test('ru gate step: the rollback is in the problem', async () => {
    const { ruGateStep } = await import('../src/scenarios/common.js');
    const gate = ruGateStep('g', 'g', () => [], { rollback: () => 'dns_change move {from: B, to: A}' });
    const r = { params: {}, vars: {} };
    assert.equal(gate.expect!([{ results: { 'B:443/x': { verdict: 'ok', note: '' } } }], r), true);
    assert.match(String(gate.expect!([{ results: { 'B:443/x': { verdict: 'blocked-ru', note: 'ТСПУ' } } }], r)), /ТСПУ[\s\S]*Откат: dns_change move/);
});
