import { Config } from '../config.js';

type G = NonNullable<Config['gitea']>;

export interface Runner {
    id: number;
    name: string;
    status: string;
    busy?: boolean;
    labels: string[];
}

async function gt<T>(g: G, method: string, path: string): Promise<{ status: number; data?: T; text: string }> {
    const res = await fetch(`${g.url}/api/v1${path}`, { method, headers: { Authorization: `token ${g.token}`, Accept: 'application/json' }, signal: AbortSignal.timeout(30_000) });
    const text = await res.text();
    let data: T | undefined;
    try {
        data = text ? (JSON.parse(text) as T) : undefined;
    } catch {
        /* not JSON */
    }
    return { status: res.status, data, text };
}

/** Runner endpoints moved between Gitea versions: admin (instance-wide) first, then the token owner's. */
const SCOPES = ['/admin/actions/runners', '/user/actions/runners'];

export async function giteaRunners(g: G): Promise<{ scope: string; runners: Runner[] }> {
    const errors: string[] = [];
    for (const scope of SCOPES) {
        const r = await gt<{ runners?: unknown[] } | unknown[]>(g, 'GET', `${scope}?limit=200`);
        if (r.status === 200) {
            const list = (Array.isArray(r.data) ? r.data : (r.data?.runners ?? [])) as Array<{ id: number; name: string; status?: string; online?: boolean; busy?: boolean; labels?: Array<{ name: string } | string> }>;
            return {
                scope,
                runners: list.map((x) => ({ id: x.id, name: x.name, status: x.status ?? (x.online ? 'online' : 'offline'), busy: x.busy, labels: (x.labels ?? []).map((l) => (typeof l === 'string' ? l : l.name)) })),
            };
        }
        errors.push(`${scope}: ${r.status}`);
    }
    throw new Error(`Gitea runner API unavailable (${errors.join(', ')}): Gitea too old or the token lacks admin rights — manage runners in the web UI`);
}

export async function giteaRunnerDelete(g: G, scope: string, id: number): Promise<void> {
    const r = await gt(g, 'DELETE', `${scope}/${id}`);
    if (r.status >= 300) throw new Error(`Gitea delete runner ${id}: ${r.status} ${r.text.slice(0, 120)}`);
}

/** A registration token for a new runner (instance-wide when the token is admin, else the user's). */
export async function giteaRegistrationToken(g: G): Promise<string> {
    const tries: Array<[string, string]> = [
        ['GET', '/admin/runners/registration-token'],
        ['POST', '/admin/actions/runners/registration-token'],
        ['GET', '/user/actions/runners/registration-token'],
        ['POST', '/user/actions/runners/registration-token'],
    ];
    const errors: string[] = [];
    for (const [m, p] of tries) {
        const r = await gt<{ token?: string }>(g, m, p);
        if (r.status < 300 && r.data?.token) return r.data.token;
        errors.push(`${m} ${p}: ${r.status}`);
    }
    throw new Error(`no runner registration token from Gitea (${errors.join(', ')})`);
}
