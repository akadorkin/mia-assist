import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Config } from '../config.js';
import { Host } from './inventory.js';
import { report } from './progress.js';

export interface ExecResult {
    host: string;
    ok: boolean;
    code: number | null;
    stdout: string;
    stderr: string;
    ms: number;
    /** ssh itself failed (exit 255): host down, Tailscale off, key refused … */
    unreachable?: boolean;
    timedOut?: boolean;
    /** Short human reason when !ok. */
    error?: string;
}

export interface ExecOptions {
    timeoutMs?: number;
    /** Variables exported at the top of the script (values travel in stdin, never in argv / ps). */
    env?: Record<string, string>;
    /** Run without sudo even if the host is configured for it. */
    noSudo?: boolean;
    /** Override the ssh target (e.g. the public IP of a fresh server in node_bootstrap). */
    via?: { address: string; user?: string; port?: number; identityFile?: string };
}

const MAX_CAPTURE = 16 * 1024 * 1024;

/** POSIX single-quote a value for the remote shell. */
export function q(s: string): string {
    return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/** Same, but plain words stay bare: for commands shown to people. */
export const shq = (s: string) => (/^[\w@%+=:,./-]+$/.test(s) ? s : q(s));

/** Common prologue: predictable output, no pager, no prompts. */
const PROLOGUE = [
    'export LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive SYSTEMD_PAGER= PAGER=cat',
    'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH',
].join('\n');

/**
 * Runs bash scripts on hosts. The script goes over stdin (`bash -s`), so there is no
 * quoting through ssh and secrets never land in the process list. The system ssh is
 * used on purpose: ~/.ssh/config aliases, the agent, ProxyJump and Tailscale SSH all
 * behave exactly as they do in the owner's terminal.
 */
export class Transport {
    constructor(private config: Config) {}

    sshArgs(host: Host, via?: ExecOptions['via']): string[] {
        const address = via?.address ?? host.address;
        const user = via ? (via.user ?? 'root') : host.user;
        const port = via ? via.port : host.port;
        const args = [
            '-o',
            'BatchMode=yes',
            '-o',
            `ConnectTimeout=${this.config.sshConnectTimeout}`,
            '-o',
            'StrictHostKeyChecking=accept-new',
            '-o',
            'ServerAliveInterval=15',
            '-o',
            'ServerAliveCountMax=4',
            '-T',
        ];
        if (port) args.push('-p', String(port));
        // the provisioning key only for the first login, and only that key (an agent full of keys trips MaxAuthTries)
        if (via?.identityFile) args.push('-i', via.identityFile.replace(/^~(?=\/)/, os.homedir()), '-o', 'IdentitiesOnly=yes');
        if (user) args.push('-l', user);
        // one connection per host for a while: the plan, the apply and the logs after it skip the handshake
        if (this.config.sshReuse && this.controlDir()) args.push('-o', 'ControlMaster=auto', '-o', `ControlPath=${this.controlDir()}/%C`, '-o', 'ControlPersist=120');
        args.push(...this.config.sshOptions, address);
        return args;
    }

    private ctlDir?: string | null;
    /** <state>/ssh (700) for the control sockets; null when it cannot be made (then no reuse). */
    private controlDir(): string | null {
        if (this.ctlDir !== undefined) return this.ctlDir;
        this.ctlDir = null;
        // a socket path must fit 104 bytes (macOS): %C is 40 characters; a long state dir falls back to the temp dir
        const uid = typeof process.getuid === 'function' ? process.getuid() : 'u';
        for (const dir of [path.join(this.config.stateDir, 'ssh'), path.join(os.tmpdir(), `mia-ssh-${uid}`)]) {
            if (dir.length + 41 >= 100) continue;
            try {
                fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
                fs.chmodSync(dir, 0o700);
                if ((fs.statSync(dir).mode & 0o077) === 0) {
                    this.ctlDir = dir;
                    break;
                }
            } catch {
                /* next candidate */
            }
        }
        return this.ctlDir;
    }

    async exec(host: Host, script: string, opts: ExecOptions = {}): Promise<ExecResult> {
        const envLines = Object.entries(opts.env ?? {}).map(([k, v]) => {
            if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) throw new Error(`bad env name ${k}`);
            return `export ${k}=${q(v)}`;
        });
        const body = [PROLOGUE, ...envLines, script, ''].join('\n');
        const sudo = host.sudo && !opts.noSudo && !(opts.via && (opts.via.user ?? 'root') === 'root');
        const remote = sudo ? 'sudo -n bash -s' : 'bash -s';

        let cmd: string;
        let args: string[];
        if (host.transport === 'local' && !opts.via) {
            cmd = sudo ? 'sudo' : 'bash';
            args = sudo ? ['-n', 'bash', '-s'] : ['-s'];
        } else {
            cmd = this.config.sshBin;
            args = [...this.sshArgs(host, opts.via), remote];
        }
        report({ kind: 'host', host: host.name, state: 'run' });
        const res = await this.spawn(host.name, cmd, args, body, opts.timeoutMs ?? this.config.commandTimeoutMs, host.transport === 'local' && !opts.via);
        report({ kind: 'host', host: host.name, state: res.ok ? 'ok' : 'fail', note: res.error, ms: res.ms });
        return res;
    }

    private spawn(name: string, cmd: string, args: string[], input: string, timeoutMs: number, local: boolean): Promise<ExecResult> {
        const started = Date.now();
        return new Promise((resolve) => {
            const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
            let stdout = '';
            let stderr = '';
            let timedOut = false;
            const timer = setTimeout(() => {
                timedOut = true;
                child.kill('SIGTERM');
                setTimeout(() => child.kill('SIGKILL'), 3000).unref();
            }, timeoutMs);
            child.stdout.on('data', (d: Buffer) => {
                if (stdout.length < MAX_CAPTURE) stdout += d.toString('utf8');
            });
            child.stderr.on('data', (d: Buffer) => {
                if (stderr.length < MAX_CAPTURE) stderr += d.toString('utf8');
            });
            child.on('error', (e) => {
                clearTimeout(timer);
                resolve({ host: name, ok: false, code: null, stdout, stderr, ms: Date.now() - started, error: `не удалось запустить ${cmd}: ${e.message}` });
            });
            child.on('close', (code) => {
                clearTimeout(timer);
                const res: ExecResult = { host: name, ok: code === 0 && !timedOut, code, stdout, stderr, ms: Date.now() - started };
                if (timedOut) {
                    res.timedOut = true;
                    res.error = `таймаут: нет ответа за ${Math.round(timeoutMs / 1000)} с`;
                } else if (code === 255 && !local) {
                    res.unreachable = true;
                    res.error = `ssh: ${sshReason(lastLine(stderr))}`;
                } else if (/sudo: (a password is required|a terminal is required)/.test(stderr)) {
                    res.error = 'sudo просит пароль: дайте ssh-пользователю NOPASSWD sudo (vps-edge-run.sh так и делает) или задайте sudo: false';
                } else if (code !== 0) {
                    res.error = `код выхода ${code}${lastLine(stderr) ? `: ${lastLine(stderr)}` : ''}`;
                }
                resolve(res);
            });
            child.stdin.on('error', () => undefined);
            child.stdin.end(input);
        });
    }
}

/** The usual ssh failures in plain words (the original line stays at the end for details). */
export function sshReason(line: string): string {
    const l = line || 'ошибка соединения';
    const known: Array<[RegExp, string]> = [
        [/Operation timed out|Connection timed out/i, 'таймаут подключения'],
        [/Connection refused/i, 'порт закрыт (sshd не слушает)'],
        [/Permission denied/i, 'нет доступа: ключ не подошёл или пользователь не тот'],
        [/Could not resolve hostname|Name or service not known|nodename nor servname/i, 'имя не резолвится (Tailscale включён? MagicDNS?)'],
        [/No route to host/i, 'нет маршрута до хоста'],
        [/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i, 'сменился ключ хоста (переустановлен?): проверьте и уберите старый из known_hosts'],
        [/Connection closed|Connection reset/i, 'соединение закрыто сервером'],
        [/tailscale.*(check|login)|tailnet policy/i, 'Tailscale SSH просит подтверждения входа'],
    ];
    const hit = known.find(([re]) => re.test(l));
    return hit ? `${hit[1]} — ${l.replace(/^ssh: /, '')}` : l;
}

function lastLine(s: string): string {
    const lines = s
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l && !/^Warning: Permanently added/.test(l));
    return (lines[lines.length - 1] ?? '').slice(0, 300);
}

/** Map over items with at most `limit` in flight; results keep input order. */
export async function pool<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
    const out: R[] = new Array(items.length);
    let next = 0;
    const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
        while (next < items.length) {
            const i = next++;
            out[i] = await fn(items[i], i);
        }
    });
    await Promise.all(workers);
    return out;
}
