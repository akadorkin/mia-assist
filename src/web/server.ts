import crypto from 'node:crypto';
import http from 'node:http';
import { Config } from '../config.js';
import { Ctx } from '../core/ctx.js';
import { Progress, withProgress } from '../core/progress.js';
import { SECRETS, loadSecrets } from '../core/secrets.js';
import { KEYWORDS, TITLES } from '../labels.js';
import { nextActions } from '../next.js';
import { CODE_RU } from '../status-view.js';
import { registry } from '../tools/helpers.js';
import { callTool, riskOf } from '../ui.js';
import { page } from './page.js';
import { fieldsOf } from './schema.js';

/**
 * `mia web`: the same tools behind a page on this machine only. The server listens on 127.0.0.1, the
 * link printed in the terminal carries a one-time token that becomes an HttpOnly SameSite=Strict
 * cookie; every API call also needs the X-Mia header (no other site can send it) and a Host of
 * 127.0.0.1/localhost (no DNS rebinding). Changes go the usual way: dry run → planHash → apply.
 *
 * Behind a proxy (`--behind-proxy --host dash.example.com`): still 127.0.0.1 only,
 * the proxy in front (Traefik on the same machine, LAN + tailnet only) is the access control, so no token;
 * only the listed Host names pass, starting work still needs X-Mia, and the page may be framed by its own
 * origin (the fleet dashboard tab). Paths in the page are relative, so it works under a prefix (/mia/).
 */

interface Job {
    id: string;
    tool: string;
    args: Record<string, unknown>;
    events: Array<{ type: 'progress'; data: Progress } | { type: 'done'; data: unknown }>;
    listeners: Set<(e: Job['events'][number]) => void>;
    done: boolean;
    at: number;
}

const QUICK = [
    { tool: 'fleet_status', title: 'Статус', preset: { target: 'all' } },
    { tool: 'apt_upgrade', title: 'Обновить пакеты' },
    { tool: 'remnanode_update', title: 'Обновить remnanode' },
    { tool: 'host_reboot', title: 'Перезагрузить' },
    { tool: 'fleet_audit', title: 'Аудит' },
    { tool: 'host_logs', title: 'Логи' },
];

export interface Web {
    url: string;
    token: string;
    server: http.Server;
    close(): Promise<void>;
}

export interface WebOptions {
    port?: number;
    /** Served by a reverse proxy on this machine: these Host names, no token (see the header comment). */
    proxyHosts?: string[];
}

export async function startWeb(deps: { ctx: Ctx; config: Config }, opts: WebOptions = {}): Promise<Web> {
    const { ctx, config } = deps;
    const token = crypto.randomBytes(24).toString('base64url');
    const jobs = new Map<string, Job>();
    let port = 0;

    const proxied = !!opts.proxyHosts?.length;
    const okHost = (h: string | undefined) =>
        !!h && (new RegExp(`^(127\\.0\\.0\\.1|localhost|\\[::1\\]):${port}$`).test(h) || (proxied && opts.proxyHosts!.includes(h.toLowerCase())));
    const cookieOk = (req: http.IncomingMessage) => proxied || (req.headers.cookie ?? '').split(/;\s*/).some((c) => c === `mia_session=${token}`);
    const send = (res: http.ServerResponse, code: number, body: unknown, type = 'application/json; charset=utf-8') => {
        res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
        res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    const readBody = (req: http.IncomingMessage): Promise<unknown> =>
        new Promise((resolve, reject) => {
            let size = 0;
            const chunks: Buffer[] = [];
            req.on('data', (c: Buffer) => {
                size += c.length;
                if (size > 1_000_000) {
                    reject(new Error('слишком большой запрос'));
                    req.destroy();
                } else chunks.push(c);
            });
            req.on('end', () => {
                try {
                    resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
                } catch {
                    reject(new Error('тело запроса — не JSON'));
                }
            });
            req.on('error', reject);
        });

    const state = () => {
        const inv = ctx.inventory();
        const hosts = [...inv.hosts.values()];
        const sec = loadSecrets({ ...process.env });
        return {
            demo: !!config.demo,
            readonly: config.readonly,
            inventory: config.inventoryFile,
            hosts: hosts.map((h) => ({ name: h.name, title: h.title, address: h.address, roles: h.roles, groups: h.groups, tags: h.tags, disabled: h.disabled, services: h.services.map((s) => s.name), logs: Object.keys(h.logs) })),
            groups: Object.fromEntries(inv.groups),
            integrations: { panel: !!config.panel, tailscaleApi: !!config.tailscaleApi, remnawaveMcp: !!config.remnawaveMcp, cloudflare: !!config.cloudflareToken },
            missing: SECRETS.filter((s) => !s.optional && sec.states.find((x) => x.name === s.name)?.source === 'missing').map((s) => s.name),
            quick: QUICK.filter((q) => registry.has(q.tool)),
            // задачи, что ещё идут: после обрыва связи или перезагрузки страница показывает их, а не зовёт «ещё раз» (AUD-16)
            running: [...jobs.values()].filter((j) => !j.done).map((j) => ({ id: j.id, tool: j.tool, title: TITLES[j.tool] ?? j.tool, apply: j.args.apply === true, target: typeof (j.args.target ?? j.args.host) === 'string' ? (j.args.target ?? j.args.host) : null, at: j.at })),
            codes: CODE_RU,
            tools: [...registry.entries()]
                .filter(([name]) => !name.startsWith('scenario_'))
                .map(([name, t]) => ({ name, title: TITLES[name] ?? name, readonly: t.readonly, planned: 'apply' in t.schema, keywords: KEYWORDS[name] ?? '', fields: fieldsOf(t.schema) }))
                .sort((a, b) => a.title.localeCompare(b.title, 'ru')),
        };
    };

    const startJob = (tool: string, args: Record<string, unknown>): Job => {
        const job: Job = { id: crypto.randomBytes(9).toString('base64url'), tool, args, events: [], listeners: new Set(), done: false, at: Date.now() };
        jobs.set(job.id, job);
        const emit = (e: Job['events'][number]) => {
            job.events.push(e);
            for (const l of job.listeners) l(e);
        };
        void withProgress(
            (p) => emit({ type: 'progress', data: p }),
            () => callTool(tool, args),
        )
            .then((res) => {
                const dry = args.apply === false;
                const data = res.data as { plan?: unknown[]; blocked?: string[]; toRun?: number } | undefined;
                const blocked = dry ? (data?.blocked ?? []) : [];
                const dead = blocked.filter((b) => /^[^:]+: unreachable:/.test(b)).map((b) => b.split(':')[0]);
                return {
                    ok: !res.isError,
                    ...(res.isError ? { error: res.text } : { data: res.data }),
                    ...(dry && !res.isError ? { risk: riskOf(tool, res.data) ?? null, unreachableOnly: blocked.length && dead.length === blocked.length ? dead : null } : {}),
                    next: res.isError || dry ? [] : nextActions(tool, args, res.data, (t) => registry.has(t)),
                };
            })
            .catch((e: unknown) => ({ ok: false, error: e instanceof Error ? e.message : String(e), next: [] }))
            .then((result) => {
                job.done = true;
                job.at = Date.now(); // уборка считает 10 минут от конца, а не от старта
                emit({ type: 'done', data: result });
            });
        return job;
    };

    // old finished jobs go after 10 minutes
    const sweep = setInterval(() => {
        for (const [id, j] of jobs) if (j.done && Date.now() - j.at > 600_000) jobs.delete(id);
    }, 60_000);
    sweep.unref();

    const server = http.createServer(async (req, res) => {
        try {
            const url = new URL(req.url ?? '/', 'http://x');
            if (!okHost(req.headers.host)) return send(res, 421, { error: 'неизвестный Host' });
            if (url.pathname === '/' && req.method === 'GET') {
                if (url.searchParams.get('t') === token) {
                    res.writeHead(302, { 'Set-Cookie': `mia_session=${token}; HttpOnly; SameSite=Strict; Path=/`, Location: '/', 'Cache-Control': 'no-store' });
                    return res.end();
                }
                if (!cookieOk(req)) return send(res, 401, '<!doctype html><meta charset="utf-8"><title>mia</title><p style="font:16px system-ui;margin:40px">Откройте ссылку, которую <b>mia web</b> напечатал в терминале.</p>', 'text/html; charset=utf-8');
                res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors ${proxied ? "'self'" : "'none'"}`);
                return send(res, 200, page(), 'text/html; charset=utf-8');
            }
            if (!url.pathname.startsWith('/api/')) return send(res, 404, { error: 'нет такого адреса' });
            // reads need the cookie; anything that starts work also needs X-Mia (EventSource cannot send headers, and needs none)
            if (!cookieOk(req) || (req.method !== 'GET' && req.headers['x-mia'] !== '1')) return send(res, 403, { error: 'нет доступа: откройте ссылку из терминала' });

            if (url.pathname === '/api/state' && req.method === 'GET') return send(res, 200, state());
            if (url.pathname === '/api/resolve' && req.method === 'GET') {
                try {
                    return send(res, 200, { hosts: ctx.inventory().resolve(url.searchParams.get('target') ?? 'all').map((h) => h.name) });
                } catch (e) {
                    return send(res, 200, { error: e instanceof Error ? e.message : String(e) });
                }
            }
            if (url.pathname === '/api/jobs' && req.method === 'POST') {
                const body = (await readBody(req)) as { tool?: unknown; args?: unknown };
                const tool = String(body.tool ?? '');
                if (!registry.has(tool)) return send(res, 400, { error: `нет инструмента ${tool}` });
                const args = body.args && typeof body.args === 'object' ? (body.args as Record<string, unknown>) : {};
                return send(res, 200, { id: startJob(tool, args).id });
            }
            const ev = url.pathname.match(/^\/api\/jobs\/([\w-]+)\/events$/);
            if (ev && req.method === 'GET') {
                const job = jobs.get(ev[1]);
                if (!job) return send(res, 404, { error: 'нет такой задачи' });
                res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
                // id = номер события: переподключившийся EventSource шлёт Last-Event-ID и получает только пропущенное
                let n = Math.max(0, parseInt(String(req.headers['last-event-id']), 10) + 1 || 0);
                const write = (e: Job['events'][number]) => res.write(`id: ${n++}\nevent: ${e.type}\ndata: ${JSON.stringify(e.data)}\n\n`);
                for (const e of job.events.slice(n)) write(e);
                if (job.done) return res.end();
                const ping = setInterval(() => res.write(': ping\n\n'), 20_000); // apt молчит минутами — без пинга прокси рвёт поток
                const l = (e: Job['events'][number]) => {
                    write(e);
                    if (e.type === 'done') {
                        job.listeners.delete(l);
                        clearInterval(ping);
                        res.end();
                    }
                };
                job.listeners.add(l);
                req.on('close', () => {
                    job.listeners.delete(l);
                    clearInterval(ping);
                });
                return;
            }
            return send(res, 404, { error: 'нет такого адреса' });
        } catch (e) {
            return send(res, 500, { error: e instanceof Error ? e.message : String(e) });
        }
    });
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(opts.port ?? 0, '127.0.0.1', () => resolve());
    });
    port = (server.address() as { port: number }).port;
    return {
        url: `http://127.0.0.1:${port}/?t=${token}`,
        token,
        server,
        close: () =>
            new Promise((resolve) => {
                clearInterval(sweep);
                server.closeAllConnections();
                server.close(() => resolve());
            }),
    };
}
