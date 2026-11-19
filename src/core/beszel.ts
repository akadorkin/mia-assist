import { Config } from '../config.js';

type B = NonNullable<Config['beszel']>;

/** Beszel hub (PocketBase): admin login, then the `systems` collection. */
export async function beszelAuth(b: B): Promise<string> {
    const body = JSON.stringify({ identity: b.email, password: b.password });
    // PocketBase ≥ 0.23 keeps admins in _superusers; the users collection also works for a Beszel admin user
    for (const path of ['/api/collections/_superusers/auth-with-password', '/api/collections/users/auth-with-password', '/api/admins/auth-with-password']) {
        const r = await fetch(`${b.url}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, signal: AbortSignal.timeout(20_000) });
        if (r.ok) return ((await r.json()) as { token: string }).token;
    }
    throw new Error('Beszel login failed (BESZEL_EMAIL / BESZEL_PASSWORD)');
}

export interface BeszelSystem {
    id: string;
    name: string;
    host: string;
    status: string;
    info?: Record<string, unknown>;
    updated?: string;
}

export async function beszelSystems(b: B): Promise<BeszelSystem[]> {
    const token = await beszelAuth(b);
    const r = await fetch(`${b.url}/api/collections/systems/records?perPage=500&sort=name`, { headers: { Authorization: token }, signal: AbortSignal.timeout(20_000) });
    if (!r.ok) throw new Error(`Beszel systems: ${r.status}`);
    return ((await r.json()) as { items: BeszelSystem[] }).items;
}

export async function beszelUpdate(b: B, id: string, patch: Record<string, unknown> | null): Promise<void> {
    const token = await beszelAuth(b);
    const r = await fetch(`${b.url}/api/collections/systems/records/${encodeURIComponent(id)}`, {
        method: patch ? 'PATCH' : 'DELETE',
        headers: { Authorization: token, 'Content-Type': 'application/json' },
        ...(patch ? { body: JSON.stringify(patch) } : {}),
        signal: AbortSignal.timeout(20_000),
    });
    if (!r.ok) throw new Error(`Beszel ${patch ? 'update' : 'delete'}: ${r.status} ${(await r.text()).slice(0, 120)}`);
}

/**
 * A new card for a machine and the agent token that belongs to it. Every system has its own token (fingerprints
 * collection): an agent started with another machine's token is refused («fingerprint mismatch» — e.g.
 * the unit and token copied from the template node). The card is owned by the same users as the existing ones.
 */
export async function beszelAddSystem(b: B, o: { name: string; host: string; port?: string }): Promise<{ id: string; token: string }> {
    const auth = await beszelAuth(b);
    const h = { Authorization: auth, 'Content-Type': 'application/json' };
    const call = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
        const r = await fetch(`${b.url}${path}`, { method, headers: h, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(20_000) });
        if (!r.ok) throw new Error(`Beszel ${method} ${path.split('?')[0]}: ${r.status} ${(await r.text()).slice(0, 160)}`);
        return (await r.json()) as T;
    };
    const like = (await call<{ items: Array<{ users?: string[] }> }>('GET', '/api/collections/systems/records?perPage=1&fields=users')).items[0];
    const sys = await call<{ id: string }>('POST', '/api/collections/systems/records', { name: o.name, host: o.host, port: o.port ?? '45876', users: like?.users ?? [] });
    const filter = encodeURIComponent(`system='${sys.id}'`);
    const fp = (await call<{ items: Array<{ id: string; token?: string }> }>('GET', `/api/collections/fingerprints/records?filter=${filter}`)).items[0];
    if (fp?.token) return { id: sys.id, token: fp.token };
    const token = crypto.randomUUID();
    if (fp) await call('PATCH', `/api/collections/fingerprints/records/${fp.id}`, { token });
    else await call('POST', '/api/collections/fingerprints/records', { system: sys.id, token });
    return { id: sys.id, token };
}
