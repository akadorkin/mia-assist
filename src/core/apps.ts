import path from 'node:path';
import { Ctx } from './ctx.js';
import { AppSpec, Host } from './inventory.js';
import { q } from './ssh.js';

export type AppName = 'jellyfin' | 'tdarr';

const DEFAULT_URL: Record<AppName, string> = {
    jellyfin: 'http://127.0.0.1:8096',
    tdarr: 'http://127.0.0.1:8265',
};

export interface AppHandle {
    host: Host;
    app: AppName;
    spec: AppSpec;
    url: string;
    /** Header carrying the key ("X-Emby-Token: …"), or '' when the app needs none. */
    authHeader: string;
}

/** `env:NAME` reads the key from this machine's environment; anything else is the key itself. */
export function resolveKey(spec: string | undefined, what: string): string {
    if (!spec) return '';
    const key = spec.startsWith('env:') ? process.env[spec.slice(4)] : spec;
    if (spec.startsWith('env:') && !key) throw new Error(`${what}: environment variable ${spec.slice(4)} is not set on the machine running mia`);
    if (key && /["\\\n\r]/.test(key)) throw new Error(`${what}: the API key contains quotes, backslashes or newlines`);
    return key ?? '';
}

export function appOf(host: Host, app: AppName): AppHandle {
    const spec = host.apps[app];
    if (!spec) {
        const have = Object.keys(host.apps);
        throw new Error(`host ${host.name} has no ${app} in the inventory (apps.${app}); ${have.length ? `it has: ${have.join(', ')}` : 'add it under hosts.' + host.name + '.apps'}`);
    }
    const key = resolveKey(spec.apiKey, `${host.name} ${app}`);
    const header = !key ? '' : app === 'jellyfin' ? `X-Emby-Token: ${key}` : `x-api-key: ${key}`;
    return { host, app, spec, url: (spec.url ?? DEFAULT_URL[app]).replace(/\/+$/, ''), authHeader: header };
}

/**
 * HTTP request made by curl ON the host (through the usual ssh transport), so the app's port
 * never has to be reachable from here. The key travels in stdin and reaches curl through a
 * process-substitution config file: it is in no command line.
 * Prints the body, then the status code on the last line.
 */
export const HTTP_SCRIPT = `
command -v curl >/dev/null || { echo "curl is not installed on this host"; echo 000; exit 3; }
cfg() { if [ -n "$AUTH_HEADER" ]; then printf 'header = "%s"\\n' "$AUTH_HEADER"; fi; }
if [ -n "$BODY" ]; then
  printf '%s' "$BODY" | curl -sS -m "$TIMEOUT" -X "$METHOD" -K <(cfg) -H 'Content-Type: application/json' -H 'Accept: application/json' --data-binary @- -w '\\n%{http_code}' "$URL"
else
  curl -sS -m "$TIMEOUT" -X "$METHOD" -K <(cfg) -H 'Accept: application/json' -w '\\n%{http_code}' "$URL"
fi
`;

export interface HttpCall {
    method: 'GET' | 'POST' | 'DELETE';
    path: string;
    body?: unknown;
    timeoutSec?: number;
}

export function httpEnv(a: AppHandle, call: HttpCall): Record<string, string> {
    return {
        METHOD: call.method,
        URL: a.url + call.path,
        BODY: call.body === undefined ? '' : JSON.stringify(call.body),
        AUTH_HEADER: a.authHeader,
        TIMEOUT: String(call.timeoutSec ?? 30),
    };
}

/** Split curl output into status + parsed body. */
export function parseHttp(stdout: string): { status: number; body: unknown; raw: string } {
    const trimmed = stdout.replace(/\s+$/, '');
    const nl = trimmed.lastIndexOf('\n');
    const status = Number(nl >= 0 ? trimmed.slice(nl + 1) : trimmed) || 0;
    const raw = nl >= 0 ? trimmed.slice(0, nl) : '';
    let body: unknown = raw;
    if (raw) {
        try {
            body = JSON.parse(raw);
        } catch {
            /* not JSON */
        }
    }
    return { status, body, raw };
}

/** Read-only call (GET, or a Tdarr cruddb read): throws on transport or HTTP errors. */
export async function appGet<T = unknown>(ctx: Ctx, a: AppHandle, call: HttpCall): Promise<T> {
    const res = await ctx.transport.exec(a.host, HTTP_SCRIPT, { env: httpEnv(a, call), timeoutMs: ((call.timeoutSec ?? 30) + 20) * 1000, noSudo: true });
    if (res.unreachable || res.timedOut) throw new Error(`${a.host.name}: ${res.error}`);
    const { status, body, raw } = parseHttp(res.stdout);
    if (status === 0) throw new Error(`${a.app} on ${a.host.name} (${a.url}) did not answer: ${(res.stderr || raw).trim().split('\n').pop()}`);
    if (status === 401 || status === 403) throw new Error(`${a.app} on ${a.host.name}: HTTP ${status} — API key missing or wrong (apps.${a.app}.apiKey)`);
    if (status >= 400) throw new Error(`${a.app} ${call.method} ${call.path}: HTTP ${status} ${raw.slice(0, 300)}`);
    return body as T;
}

// ---------------------------------------------------------------- docker path mapping

export interface Mount {
    src: string;
    dst: string;
    rw: boolean;
}

/** Bind mounts of a container (host path → container path). */
export async function containerMounts(ctx: Ctx, host: Host, container: string): Promise<Mount[]> {
    const res = await ctx.transport.exec(host, `docker inspect --format '{{range .Mounts}}{{.Source}}\t{{.Destination}}\t{{.RW}}\n{{end}}' "$C"`, {
        env: { C: container },
        timeoutMs: 30_000,
    });
    if (!res.ok) throw new Error(`${host.name}: cannot inspect container ${container}: ${res.error}`);
    return res.stdout
        .split('\n')
        .filter(Boolean)
        .map((l) => {
            const [src, dst, rw] = l.split('\t');
            return { src, dst, rw: rw === 'true' };
        });
}

/** Host path → path inside the container, via the longest matching bind mount. */
export function toContainerPath(mounts: Mount[], hostPath: string): { path: string; mount: Mount } | undefined {
    const p = path.posix.normalize(hostPath).replace(/\/+$/, '') || '/';
    const hits = mounts.filter((m) => p === m.src || p.startsWith(m.src.replace(/\/+$/, '') + '/')).sort((a, b) => b.src.length - a.src.length);
    const m = hits[0];
    if (!m) return undefined;
    return { path: path.posix.join(m.dst, p.slice(m.src.replace(/\/+$/, '').length)) || '/', mount: m };
}

/** Container path → host path (to show where a library really lives). */
export function toHostPath(mounts: Mount[], containerPath: string): string | undefined {
    const p = path.posix.normalize(containerPath).replace(/\/+$/, '') || '/';
    const m = mounts.filter((x) => p === x.dst || p.startsWith(x.dst.replace(/\/+$/, '') + '/')).sort((a, b) => b.dst.length - a.dst.length)[0];
    return m ? path.posix.join(m.src, p.slice(m.dst.replace(/\/+$/, '').length)) : undefined;
}

/**
 * Where a folder given by the owner lives for the app: the path the app must be told
 * (inside its container when it runs in docker) and checks that it exists on both sides.
 */
export async function locateFolder(
    ctx: Ctx,
    a: AppHandle,
    given: string,
): Promise<{ appPath: string; hostPath?: string; problems: string[]; notes: string[]; stats?: string }> {
    const problems: string[] = [];
    const notes: string[] = [];
    if (!given.startsWith('/')) return { appPath: given, problems: ['path must be absolute'], notes };
    if (given.includes(',')) problems.push('paths with commas are not supported by the API');
    let appPath = given;
    let hostPath: string | undefined = given;
    const container = a.spec.container;
    if (container) {
        const mounts = await containerMounts(ctx, a.host, container);
        const asHost = toContainerPath(mounts, given);
        const asContainer = toHostPath(mounts, given);
        if (asHost) {
            appPath = asHost.path;
            notes.push(`host ${given} → ${container}:${appPath}${asHost.mount.rw ? '' : ' (read-only mount)'}`);
        } else if (asContainer) {
            hostPath = asContainer;
            notes.push(`${container}:${given} = host ${asContainer}`);
        } else {
            problems.push(`${given} is not under any mount of container ${container} (mounts: ${mounts.map((m) => `${m.src}→${m.dst}`).join(', ') || 'none'}); add a volume first`);
            hostPath = undefined;
        }
    }
    const check = await ctx.transport.exec(
        a.host,
        `if [ -n "$HP" ]; then if [ -d "$HP" ]; then echo "host: $(find "$HP" -maxdepth 3 -type f 2>/dev/null | head -n 20000 | wc -l) files (depth≤3, capped at 20000)"; else echo "HOST_MISSING"; fi; fi
if [ -n "$C" ]; then docker exec "$C" test -d "$AP" && echo "container: ok" || echo "CONTAINER_MISSING"; fi`,
        { env: { HP: hostPath ?? '', C: container ?? '', AP: appPath }, timeoutMs: 60_000 },
    );
    if (check.stdout.includes('HOST_MISSING')) problems.push(`${hostPath} does not exist on ${a.host.name}`);
    if (check.stdout.includes('CONTAINER_MISSING')) problems.push(`${appPath} is not visible inside ${container}`);
    const stats = check.stdout.split('\n').find((l) => l.startsWith('host: '))?.slice(6);
    return { appPath, hostPath, problems, notes, stats };
}

export { q };
