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
