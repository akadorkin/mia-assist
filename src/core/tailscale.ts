import { Config } from '../config.js';

/** Tailscale API v2 (admin): every device of the tailnet, not only what this machine sees. */
export interface TsApiDevice {
    id: string;
    nodeId?: string;
    name: string;
    hostname: string;
    addresses: string[];
    os?: string;
    clientVersion?: string;
    updateAvailable?: boolean;
    lastSeen?: string;
    expires?: string;
    keyExpiryDisabled?: boolean;
    authorized?: boolean;
    tags?: string[];
    user?: string;
    connectedToControl?: boolean;
}

const BASE = 'https://api.tailscale.com/api/v2';

async function call<T>(key: string, method: string, url: string, body?: unknown): Promise<T> {
    const res = await fetch(url, {
        method,
        headers: { Authorization: `Bearer ${key}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(30_000),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Tailscale API ${method} ${url.replace(BASE, '')}: ${res.status} ${text.slice(0, 200)}`);
    return (text ? JSON.parse(text) : {}) as T;
}

export async function tsDevices(api: NonNullable<Config['tailscaleApi']>): Promise<TsApiDevice[]> {
    const r = await call<{ devices: TsApiDevice[] }>(api.key, 'GET', `${BASE}/tailnet/${encodeURIComponent(api.tailnet)}/devices?fields=all`);
    return r.devices ?? [];
}

export async function tsDeleteDevice(api: NonNullable<Config['tailscaleApi']>, id: string): Promise<void> {
    await call(api.key, 'DELETE', `${BASE}/device/${encodeURIComponent(id)}`);
}

/**
 * A one-time, preauthorized auth key that lives an hour: what a server needs to join the tailnet once.
 * A stored reusable TAILSCALE_AUTH_KEY expires quietly, a fresh key never does.
 */
export async function tsCreateAuthKey(api: NonNullable<Config['tailscaleApi']>, description: string): Promise<string> {
    const r = await call<{ key?: string }>(api.key, 'POST', `${BASE}/tailnet/${encodeURIComponent(api.tailnet)}/keys`, {
        capabilities: { devices: { create: { reusable: false, ephemeral: false, preauthorized: true } } },
        expirySeconds: 3600,
        description: description.replace(/[^\w .-]/g, '-').slice(0, 50),
    });
    if (!r.key) throw new Error('Tailscale API did not return a key');
    return r.key;
}

/** Days until the node key expires (negative = expired), undefined when expiry is off. */
export function keyDaysLeft(d: { expires?: string; keyExpiryDisabled?: boolean }, now = Date.now()): number | undefined {
    if (d.keyExpiryDisabled || !d.expires || d.expires.startsWith('0001')) return undefined;
    return Math.floor((Date.parse(d.expires) - now) / 86_400_000);
}
