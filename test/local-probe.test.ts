import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { Inventory } from '../src/core/inventory.js';
import { probeHost } from '../src/core/probe.js';
import { Transport } from '../src/core/ssh.js';

// Runs the real probe.sh through the local transport: catches bash errors and
// parser/format drift on whatever Linux runs the tests (CI: ubuntu-latest).
test('probe.sh runs locally and parses', { skip: process.platform !== 'linux' }, async () => {
    const inv = new Inventory('f', { hosts: { me: { transport: 'local', roles: ['remnanode'] } } });
    const transport = new Transport(loadConfig({}));
    const f = await probeHost(transport, inv.get('me'), 'full', 60_000);
    assert.equal(f.reachable, true, f.error);
    assert.equal(f.error, undefined);
    assert.ok(f.kernel && f.os && f.cpus && f.cpus > 0);
    assert.ok(f.mem && f.mem.totalMiB > 0);
    assert.ok(f.disks.length > 0);
    assert.ok(f.packages && Object.keys(f.packages).length > 10, 'dpkg packages listed');
    assert.ok(f.files && Object.keys(f.files).some((p) => p.startsWith('/etc/')), 'tracked files read');
    assert.ok(f.services.some((s) => s.name === 'remnanode'), 'inventory services probed');
});
