import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { scrub, sshTargets, writeDigest } from '../src/core/digest.js';

test('ssh targets: options with arguments skipped, user/port kept, non-invocations ignored', () => {
    assert.deepEqual(sshTargets('ssh -o BatchMode=yes -p 2022 root@10.0.0.5 uptime'), ['root@10.0.0.5:2022']);
    assert.deepEqual(sshTargets('sudo ssh -T -i ~/.ssh/k home "docker ps"; ssh -l pi rpi'), ['home', 'pi@rpi']);
    assert.deepEqual(sshTargets('which ssh sshd; apt install openssh-client'), []);
    assert.deepEqual(sshTargets('x=$(ssh node-a hostname)'), ['node-a']);
});

test('transcript scrubbing', () => {
    const jwt = 'eyJub2RlQ2VydFBlbSI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJQm';
    assert.equal(scrub(`grep '${jwt}' f`), `grep '«redacted»' f`);
    assert.equal(scrub('token AbCdEf0123456789GhIjKlMnOpQrStUvWx99'), 'token «redacted»');
    assert.equal(scrub('-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----'), '«private key redacted»');
    const sha = 'sha256:0cdf386dd49f360fc885bb34bde21132e478e40f0deac62d616086ec0fa9257e';
    assert.equal(scrub(sha), sha, 'hex digests stay');
    assert.equal(scrub('uuid 7107622e-96c0-5249-a457-6195bd194a42'), 'uuid 7107622e-96c0-5249-a457-6195bd194a42');
    assert.equal(scrub('/home/user/mia-assist/src/core/digest.ts'), '/home/user/mia-assist/src/core/digest.ts');
});

test('digest of a transcript: prompts, commands, entities, no secrets', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-dig-'));
    fs.mkdirSync(path.join(root, 'projects', '-Users-me'), { recursive: true });
    const jwt = 'eyJub2RlQ2VydFBlbSI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJQm';
    const lines = [
        { type: 'user', timestamp: '2026-09-05T21:03:10Z', cwd: '/Users/me', message: { role: 'user', content: 'Сделай коллекцию клипов 90-х в Jellyfin на home' } },
        { type: 'assistant', timestamp: '2026-09-05T21:04:00Z', message: { content: [{ type: 'text', text: 'Смотрю библиотеки.' }, { type: 'tool_use', name: 'Bash', input: { command: `ssh home 'docker logs --tail 50 jellyfin; ls /mnt/media/clips' && ssh -p 2222 root@203.0.113.9 "echo SECRET_KEY=${jwt}"` } }] } },
        { type: 'user', timestamp: '2026-09-05T21:04:05Z', message: { content: [{ type: 'tool_result', content: 'noise' }] } },
        { type: 'assistant', timestamp: '2026-09-05T21:05:00Z', message: { content: [{ type: 'tool_use', name: 'Bash', input: { command: 'ssh home "systemctl restart smbd && cd /opt/tdarr && docker compose up -d"' } }, { type: 'tool_use', name: 'Edit', input: { file_path: '/Users/me/notes.md' } }] } },
        { type: 'summary', summary: 'Клипы 90-х в Jellyfin' },
    ];
    fs.writeFileSync(path.join(root, 'projects', '-Users-me', 's1.jsonl'), lines.map((l) => JSON.stringify(l)).join('\n') + '\n{broken json\n');
    const out = path.join(root, 'out');
    const r = writeDigest(path.join(root, 'projects'), out);
    assert.equal(r.sessions, 1);
    const e = JSON.parse(fs.readFileSync(path.join(out, 'entities.json'), 'utf8'));
    assert.deepEqual(Object.keys(e.sshTargets).sort(), ['home', 'root@203.0.113.9:2222']);
    assert.ok(e.containers.jellyfin);
    assert.ok(e.units.smbd);
    assert.ok(e.paths['/mnt/media/clips']);
    assert.ok(e.composeDirs['/opt/tdarr']);
    assert.ok(e.ips['203.0.113.9']);
    const all = fs.readdirSync(path.join(out, 'sessions')).map((f) => fs.readFileSync(path.join(out, 'sessions', f), 'utf8')).join('') + fs.readFileSync(path.join(out, 'entities.md'), 'utf8');
    assert.ok(!all.includes(jwt.slice(0, 20)), 'secret masked');
    assert.match(all, /# Клипы 90-х в Jellyfin/);
    assert.match(all, /Сделай коллекцию клипов/);
    assert.match(all, /\/Users\/me\/notes\.md/);
    assert.doesNotMatch(all, /noise/, 'tool results are not copied');
});
