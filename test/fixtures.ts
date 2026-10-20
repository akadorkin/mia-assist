import { ExecResult } from '../src/core/ssh.js';

/** `ufw status verbose` as vps-edge-run.sh leaves it on a tailscale-only remnanode. */
export const UFW_BASELINE = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), allow (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
80/tcp on eth0             ALLOW IN    Anywhere
80/udp on eth0             ALLOW IN    Anywhere
443/tcp on eth0            ALLOW IN    Anywhere
443/udp on eth0            ALLOW IN    Anywhere
22/tcp on eth0             DENY IN     Anywhere
2222/tcp on eth0           DENY IN     Anywhere
9100/tcp on eth0           DENY IN     Anywhere
Anywhere on tailscale0     ALLOW IN    Anywhere
Anywhere                   REJECT IN   203.0.113.7                # banned
80/tcp (v6) on eth0        ALLOW IN    Anywhere (v6)
443/tcp (v6) on eth0       ALLOW IN    Anywhere (v6)
Anywhere (v6) on tailscale0 ALLOW IN    Anywhere (v6)

Anywhere                   ALLOW OUT   Anywhere on tailscale0
6881:6999/tcp              DENY OUT    Anywhere
`;

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

/** Build probe output from records, as probe.sh would print it. */
export function probeOutput(rec: Record<string, string>): string {
    return Object.entries({ probe_version: '2', mode: 'quick', ...rec, done: '1' })
        .map(([k, v]) => `${k}\t${b64(v)}`)
        .join('\n');
}

export function execOk(stdout: string, host = 'h'): ExecResult {
    return { host, ok: true, code: 0, stdout, stderr: '', ms: 5 };
}

const NOW = 1_790_000_000;

/** A remnanode exactly as the baseline wants it. */
export function healthyNodeRecords(overrides: Record<string, string> = {}): Record<string, string> {
    return {
        whoami: 'root',
        hostname: 'nl-1',
        os: 'Ubuntu 24.04.1 LTS',
        kernel: '6.8.0-45-generic',
        arch: 'x86_64',
        now: String(NOW),
        uptime: '864000.5',
        loadavg: '0.20 0.30 0.25 1/300 12345',
        cpus: '2',
        meminfo: 'MemTotal:        4000000 kB\nMemAvailable:    3000000 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB',
        df: '/dev/vda1 ext4 41000000 12000000 29000000 30% /',
        apt_upgradable: '',
        units: [
            'ssh|active|enabled',
            'docker|active|enabled',
            'tailscaled|active|enabled',
            'fail2ban|active|enabled',
            'node_exporter|active|enabled',
            'beszel-agent|active|enabled',
            'ipset-load|active|enabled',
            'apt-daily-upgrade.timer|active|enabled',
            'ufw|active|enabled',
            'cron|active|enabled',
            'update-roscomvpn-geo.timer|active|enabled',
            'update-roscomvpn-geo.service|inactive|static',
        ].join('\n'),
        failed_units: '',
        geo_service: 'Result=success\nExecMainStatus=0',
        timedate: 'NTPSynchronized=yes\nTimezone=Europe/Moscow',
        ufw: UFW_BASELINE,
        listen: [
            'tcp   LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=1,fd=3))',
            'udp   UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=1,fd=4))',
            'tcp   LISTEN 0 4096 *:2222 *:* users:(("node",pid=2,fd=5))',
            'tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=3))',
            'tcp   LISTEN 0 4096 *:9100 *:* users:(("node_exporter",pid=4,fd=3))',
            'udp   UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=5,fd=13))',
        ].join('\n'),
        sshd: 'port 22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes',
        fail2ban: 'sshd 0 12\nsshd-fast 1 40\nrecidive 0 3',
        sysctl: 'net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\nnet.ipv4.ip_forward = 1\nnet.netfilter.nf_conntrack_max = 262144\nnet.netfilter.nf_conntrack_count = 1200',
        ipsets: 'whitelist 1200\nblacklist_ru 1150\nblacklist_dangerous 340',
        blacklist_cron: '0 */2 * * * root /usr/local/bin/ufw-blacklist.sh',
        blacklist_script: String(NOW - 86400),
        mgmt_chain: '7',
        mgmt_jump: '1',
        mgmt_list: '22 2222 9100 45876',
        apt_auto: 'APT::Periodic::Update-Package-Lists "1"\nAPT::Periodic::Unattended-Upgrade "1"\nUnattended-Upgrade::Automatic-Reboot "false"',
        apt_origins: '${distro_id}:${distro_codename}\n${distro_id}:${distro_codename}-security\n${distro_id}ESMApps:${distro_codename}-apps-security',
        uu_installed: '1',
        tailscale: JSON.stringify({ BackendState: 'Running', Self: { DNSName: 'nl-1.tailnet.example.', TailscaleIPs: ['198.51.100.2'], Online: true } }),
        tailscale_version: '1.80.0',
        docker_version: '27.3.1',
        compose_version: '2.29.7',
        docker_ps: 'remnanode\tremnawave/node:latest\trunning\tUp 3 days',
        docker_inspect: '/remnanode\tsha256:aaa\tremnawave/node:latest\t2026-09-01T00:00:00Z\t0\t<nil>',
        docker_images_used: 'remnawave/node:latest\tsha256:aaa\tremnawave/node@sha256:ddd\t2026-08-30',
        remnanode_compose: 'image=remnawave/node:latest\nnode_port=2222\nsecret_key=present\ngeo_volumes=2\ncert_volume=1\nnetwork_host=1',
        geo_files: `/opt/remnanode/roscomvpn-geoip.dat ${NOW - 7200} 100000\n/opt/remnanode/roscomvpn-geosite.dat ${NOW - 7200} 200000`,
        certs: `remnanode\t${NOW + 60 * 86400}\tCN = nl1.example.com\tDNS:nl1.example.com`,
        services: 'remnanode\tcompose=remnanode:running container=running\ncertbot\tcompose=none\ngeo-updater\t unit=inactive/static\ndocker\t unit=active/enabled',
        ...overrides,
    };
}
