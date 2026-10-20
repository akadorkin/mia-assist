import assert from 'node:assert/strict';
import { test } from 'node:test';
import { REDACTED, redact, redactText } from '../src/core/output.js';
import { parseProbe } from '../src/core/probe.js';
import { diffState, groupChanges, snapshotState } from '../src/core/snapshot.js';
import { UFW_BASELINE, execOk, healthyNodeRecords, probeOutput } from './fixtures.js';

const full = (over: Record<string, string> = {}) =>
    parseProbe(
        'nl-1',
        execOk(
            probeOutput({
                ...healthyNodeRecords(),
                mode: 'full',
                packages: 'openssl\t3.0.13-0ubuntu3.4\nnginx\t1.24\ncurl\t8.5.0',
                enabled_units: 'docker.service\nssh.service',
                users: 'root:0:/bin/bash\nops:1000:/usr/bin/zsh',
                authorized_keys: '/home/ops\tSHA256:abc\tme@laptop\t(ED25519)',
                'file:/opt/remnanode/docker-compose.yml': 'sha=1111 size=100\nservices:\n  remnanode:\n    environment:\n      - NODE_PORT=2222\n      - SECRET_KEY=supersecretvalue',
                'file:/usr/bin/big': 'sha=2222 size=9999999\n(binary or large: content not tracked)',
                ...over,
            }),
        ),
        'full',
    );

const PG = 'postgresql' + '://'; // split so secret scanners do not flag the fixtures

test('snapshot keeps configuration, drops weather', () => {
    const s = snapshotState(full()) as Record<string, Record<string, unknown>>;
    assert.equal((s.packages as Record<string, string>).openssl, '3.0.13-0ubuntu3.4');
    assert.ok(!('nf_conntrack_count' in s.sysctl) && !('net.netfilter.nf_conntrack_count' in s.sysctl));
    assert.equal((s.counters as Record<string, number>).ufwBans, 1, 'the fail2ban REJECT rule is counted, not diffed');
    assert.ok(!(s.firewall.ufw as { rules: string[] }).rules.some((r) => r.includes('203.0.113.7')));
    assert.equal((s.files as Record<string, string>)['/usr/bin/big'], 'sha:2222');
});

test('diff: package churn, new key, file lines, sysctl, bans ignored', () => {
    const a = redact(snapshotState(full()));
    const b = redact(
        snapshotState(
            full({
                packages: 'openssl\t3.0.13-0ubuntu3.5\nnginx\t1.24\nhtop\t3.3',
                authorized_keys: '/home/ops\tSHA256:abc\tme@laptop\t(ED25519)\n/root\tSHA256:zzz\tintruder\t(RSA)',
                'file:/opt/remnanode/docker-compose.yml': 'sha=3333 size=100\nservices:\n  remnanode:\n    environment:\n      - NODE_PORT=3333\n      - SECRET_KEY=othersecret',
                sysctl: 'net.ipv4.tcp_congestion_control = cubic\nnet.netfilter.nf_conntrack_count = 99999',
                ufw: UFW_BASELINE.replace('203.0.113.7', '198.51.100.9'),
            }),
        ),
    );
    const changes = diffState(a, b);
    const paths = changes.map((c) => `${c.kind} ${c.path}`);
    assert.ok(paths.includes('changed packages.openssl'));
    assert.ok(paths.includes('added packages.htop'));
    assert.ok(paths.includes('removed packages.curl'));
    assert.ok(paths.includes('added access.authorizedKeys'));
    assert.ok(paths.includes('changed sysctl.net.ipv4.tcp_congestion_control'));
    assert.ok(!paths.some((p) => p.includes('conntrack_count')));
    assert.ok(!paths.some((p) => p.includes('counters') || p.includes('198.51.100.9')), 'a different banned IP is not a change');

    const file = changes.find((c) => c.path === 'files./opt/remnanode/docker-compose.yml')!;
    assert.deepEqual(file.linesAdded, ['      - NODE_PORT=3333']);
    assert.deepEqual(file.linesRemoved, ['      - NODE_PORT=2222']);
    assert.ok(!JSON.stringify(changes).includes('othersecret'), 'secret changes never show up (both sides masked)');

    const g = groupChanges(changes) as Record<string, unknown>;
    assert.deepEqual((g.packages as Record<string, unknown>).upgraded, 1);
    assert.deepEqual((g.packages as Record<string, unknown>).installedList, ['htop 3.3']);
});

test('identical states diff to nothing', () => {
    assert.deepEqual(diffState(redact(snapshotState(full())), redact(snapshotState(full()))), []);
});

test('redaction: text patterns and keys', () => {
    assert.equal(redactText('- SECRET_KEY=abc'), `- SECRET_KEY=${REDACTED}`);
    assert.equal(redactText('CRIT ssh.password: sshd PasswordAuthentication is on'), 'CRIT ssh.password: sshd PasswordAuthentication is on');
    assert.equal(redactText('BOT_TOKEN=1:x'), `BOT_TOKEN=${REDACTED}`);
    assert.equal(redactText('db_password: hunter2'), `db_password: ${REDACTED}`);
    assert.equal(redactText('"privateKey": "AAA"'), `"privateKey": "${REDACTED}"`);
    assert.equal(redactText('--authkey=' + ['tskey', 'auth', 'kX1', 'abc'].join('-')), `--authkey=tskey-auth-${REDACTED}`);
    assert.equal(redactText('Total banned: 5; token bucket'), 'Total banned: 5; token bucket');
    assert.equal(redactText(`DATABASE_URL=${PG}postgres:hunter2@db:5432/x`), `DATABASE_URL=${PG}postgres:${REDACTED}@db:5432/x`);
    assert.equal(redactText('see https://example.com/path'), 'see https://example.com/path');
    assert.equal(redactText('vless://9847f971-6fa8-45f5-890c-1e832885e808@nl1.example.com:443?security=reality#NL'), `vless://${REDACTED}@nl1.example.com:443?security=reality#NL`);
    assert.equal(redactText('hy2://s3cretPass@de.example.com:443'), `hy2://${REDACTED}@de.example.com:443`);
    assert.equal(redactText('vmess://eyJhZGQiOiJubDEuZXhhbXBsZS5jb20ifQ=='), `vmess://${REDACTED}`);
    assert.equal(redactText('curl https://panel.example.com/api/sub/Ab3dEf9hJk'), `curl https://panel.example.com/api/sub/${REDACTED}`);
    assert.equal(redactText('/api/subscriptions list'), '/api/subscriptions list');
    assert.equal(redactText(`curl -s -u 'admin:Hunter22x' http://rpi:3000/api`), `curl -s -u 'admin:${REDACTED}' http://rpi:3000/api`);
    assert.equal(redactText(`G=http://rpi:3000; A='admin:Hunter22x'; curl -u "$A" "$G/api/search"`), `G=http://rpi:3000; A='admin:${REDACTED}'; curl -u "$A" "$G/api/search"`);
    assert.equal(redactText('Authorization: Basic YWRtaW46aHVudGVyMg=='), `Authorization: Basic ${REDACTED}`);
    assert.equal(redactText('-H "Authorization: token 0123456789abcdef0123456789abcdef01234567"'), `-H "Authorization: token ${REDACTED}"`);
    assert.equal(redactText('GET /api/v1/repos?access_token=0123456789abcdef0123456789abcdef01234567&x=1'), `GET /api/v1/repos?access_token=${REDACTED}&x=1`);
    assert.equal(redactText('commit 0123456789abcdef0123456789abcdef01234567'), 'commit 0123456789abcdef0123456789abcdef01234567', 'bare git SHAs stay');
    assert.equal(redactText('sshpass -p "S3cret" ssh root@x'), `sshpass -p "${REDACTED}" ssh root@x`);
    assert.equal(redactText('ключ Ab12Cd34-Ef56Gh78-Ij90Kl12 держи'), `ключ ${REDACTED} держи`);
    assert.equal(redactText('read -rs "Ab12Cd34-Ef56Gh78-"; echo'), `read -rs "${REDACTED}"; echo`);
    assert.equal(redactText('uuid 9847f971-6fa8-45f5-890c-1e832885e808 node-panel ssh -u root'), 'uuid 9847f971-6fa8-45f5-890c-1e832885e808 node-panel ssh -u root');
    assert.deepEqual(redact({ secretKey: 'x', nested: [{ SECRET_KEY: 'y', ok: true, secret_key: 'present' }] }), {
        secretKey: REDACTED,
        nested: [{ SECRET_KEY: REDACTED, ok: true, secret_key: 'present' }],
    });
});
