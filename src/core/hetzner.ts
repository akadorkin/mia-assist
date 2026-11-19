import net from 'node:net';

/** Hetzner Cloud API (HETZNER_API_TOKEN, read/write): buy and delete the fleet's cloud servers. */
const API = 'https://api.hetzner.cloud/v1';

export interface HzServer {
    id: number;
    name: string;
    status: string;
    type: string;
    location: string;
    ipv4?: string;
    /** First address of the routed /64 (what the image configures on eth0). */
    ipv6?: string;
}

export class HzError extends Error {
    constructor(
        message: string,
        public code: string,
    ) {
        super(message);
    }
}

/** Network failures that happened before the request could reach Hetzner: safe to repeat even a POST. */
const NOT_SENT = new Set(['UND_ERR_CONNECT_TIMEOUT', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH']);

async function hz<T>(token: string, method: string, path: string, body?: unknown): Promise<T> {
    let res: Response | undefined;
    // seen in practice: the API answered every other time and a runbook stopped on «fetch failed»,
    // once skipping a server deletion. Reads are repeated on any network error, writes only when nothing was sent.
    for (let attempt = 1; ; attempt++) {
        try {
            res = await fetch(`${API}${path}`, {
                method,
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                ...(body ? { body: JSON.stringify(body) } : {}),
                signal: AbortSignal.timeout(30_000),
            });
            break;
        } catch (e) {
            const code = String((e as { cause?: { code?: string } }).cause?.code ?? '');
            if (attempt >= 5 || !(method === 'GET' || NOT_SENT.has(code))) throw new Error(`Hetzner ${method} ${path.split('?')[0]}: сеть — ${e instanceof Error ? e.message : String(e)}${code ? ` (${code})` : ''}, попыток ${attempt}`);
            await new Promise((ok) => setTimeout(ok, hzRetryMs * attempt));
        }
    }
    const j = (await res.json().catch(() => ({}))) as T & { error?: { code?: string; message?: string } };
    if (!res.ok || j.error) throw new HzError(`Hetzner ${method} ${path.split('?')[0]}: ${res.status} ${j.error?.code ?? ''} ${j.error?.message ?? ''}`.trim(), j.error?.code ?? String(res.status));
    return j;
}

/** Pause between retries, ms × attempt (tests set it to 0). */
export let hzRetryMs = 1500;
export const setHzRetryMs = (ms: number) => (hzRetryMs = ms);

type RawServer = { id: number; name: string; status: string; server_type: { name: string }; location?: { name: string }; datacenter?: { location: { name: string } }; public_net: { ipv4?: { ip: string } | null; ipv6?: { ip: string } | null } };

const serverOf = (s: RawServer): HzServer => ({
    id: s.id,
    name: s.name,
    status: s.status,
    type: s.server_type.name,
    location: s.location?.name ?? s.datacenter?.location.name ?? '?',
    ipv4: s.public_net.ipv4?.ip,
    ipv6: s.public_net.ipv6?.ip ? s.public_net.ipv6.ip.replace(/::\/\d+$/, '::1') : undefined,
});

export async function hzServerByName(token: string, name: string): Promise<HzServer | undefined> {
    const r = await hz<{ servers: RawServer[] }>(token, 'GET', `/servers?name=${encodeURIComponent(name)}`);
    return r.servers[0] ? serverOf(r.servers[0]) : undefined;
}

/** Ids of the named ssh keys; `pub` (this machine's key) is registered under its name when its body is not there yet. */
export async function hzSshKeys(token: string, names: string[], pub?: { name: string; key: string }, register = false): Promise<{ ids: number[]; missing: string[]; toRegister?: string }> {
    const { ssh_keys } = await hz<{ ssh_keys: Array<{ id: number; name: string; public_key: string }> }>(token, 'GET', '/ssh_keys?per_page=50');
    const ids = names.map((n) => ssh_keys.find((k) => k.name === n)?.id);
    const body = (k: string) => k.trim().split(/\s+/).slice(0, 2).join(' ');
    let toRegister: string | undefined;
    if (pub) {
        const have = ssh_keys.find((k) => body(k.public_key) === body(pub.key));
        if (have) ids.push(have.id);
        else if (register) ids.push((await hz<{ ssh_key: { id: number } }>(token, 'POST', '/ssh_keys', { name: pub.name, public_key: pub.key.trim() })).ssh_key.id);
        else toRegister = pub.name;
    }
    return { ids: [...new Set(ids.filter((x): x is number => x !== undefined))], missing: names.filter((_, i) => ids[i] === undefined), ...(toRegister ? { toRegister } : {}) };
}

/** Codes that mean «not this type here, try the next pair». */
const NEXT = new Set(['resource_unavailable', 'placement_error', 'server_type_unavailable', 'unsupported_location_for_server_type', 'invalid_input']);

/**
 * Create a server: the first type × location pair Hetzner has, in the given order. Returns once the server
 * runs; `tried` lists the pairs that were refused.
 */
export async function hzCreate(
    token: string,
    o: { name: string; types: string[]; locations: string[]; image: string | number; sshKeys: number[]; labels?: Record<string, string>; userData?: string },
    waitMs = 120_000,
): Promise<HzServer & { tried: string[] }> {
    const tried: string[] = [];
    for (const type of o.types)
        for (const location of o.locations) {
            let raw: RawServer;
            try {
                raw = (await hz<{ server: RawServer }>(token, 'POST', '/servers', { name: o.name, server_type: type, location, image: o.image, ssh_keys: o.sshKeys, labels: o.labels ?? {}, start_after_create: true, ...(o.userData ? { user_data: o.userData } : {}) })).server;
            } catch (e) {
                if (e instanceof HzError && NEXT.has(e.code)) {
                    tried.push(`${type}@${location}: ${e.code}`);
                    continue;
                }
                throw e;
            }
            const until = Date.now() + waitMs;
            let s = serverOf(raw);
            while (s.status !== 'running' && Date.now() < until) {
                await new Promise((ok) => setTimeout(ok, 2000));
                s = serverOf((await hz<{ server: RawServer }>(token, 'GET', `/servers/${raw.id}`)).server);
            }
            if (s.status !== 'running') throw new Error(`Hetzner: ${o.name} (#${s.id}) is still ${s.status} after ${waitMs / 1000}s`);
            return { ...s, tried };
        }
    throw new Error(`Hetzner has none of ${o.types.join(', ')} in ${o.locations.join(', ')}: ${tried.join('; ')}`);
}

export async function hzDelete(token: string, id: number): Promise<void> {
    await hz(token, 'DELETE', `/servers/${id}`);
}

/** Wait until a TCP port accepts connections (sshd of a server that has just booted). */
export async function waitPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
    const until = Date.now() + timeoutMs;
    for (;;) {
        const ok = await new Promise<boolean>((resolve) => {
            const s = net.connect({ host, port, timeout: 3000 });
            s.once('connect', () => (s.destroy(), resolve(true)));
            s.once('timeout', () => (s.destroy(), resolve(false)));
            s.once('error', () => resolve(false));
        });
        if (ok) return true;
        if (Date.now() >= until) return false;
        await new Promise((r) => setTimeout(r, 2000));
    }
}

export interface HzImage {
    id: number;
    description: string;
    created: string;
    sizeGb?: number;
    diskGb?: number;
}

/** Snapshots carrying a label (e.g. «role=node-image»), newest first. */
export async function hzSnapshots(token: string, labelSelector: string): Promise<HzImage[]> {
    const r = await hz<{ images: Array<{ id: number; description: string; created: string; image_size?: number; disk_size?: number; status: string }> }>(token, 'GET', `/images?type=snapshot&status=available&label_selector=${encodeURIComponent(labelSelector)}&per_page=50`);
    return r.images.map((i) => ({ id: i.id, description: i.description, created: i.created, sizeGb: i.image_size, diskGb: i.disk_size })).sort((a, b) => b.created.localeCompare(a.created));
}

/** Snapshot of a server; returns when the image is ready (minutes for a few GB). */
export async function hzSnapshot(token: string, serverId: number, description: string, labels: Record<string, string>, waitMs = 900_000): Promise<HzImage> {
    const r = await hz<{ image: { id: number }; action: { id: number } }>(token, 'POST', `/servers/${serverId}/actions/create_image`, { type: 'snapshot', description, labels });
    const until = Date.now() + waitMs;
    for (;;) {
        const a = (await hz<{ action: { status: string; error?: { message?: string } } }>(token, 'GET', `/actions/${r.action.id}`)).action;
        if (a.status === 'success') break;
        if (a.status === 'error') throw new Error(`Hetzner snapshot: ${a.error?.message ?? 'error'}`);
        if (Date.now() >= until) throw new Error(`Hetzner snapshot #${r.image.id} is still being made after ${waitMs / 1000}s`);
        await new Promise((ok) => setTimeout(ok, 5000));
    }
    const i = (await hz<{ image: { id: number; description: string; created: string; image_size?: number; disk_size?: number } }>(token, 'GET', `/images/${r.image.id}`)).image;
    return { id: i.id, description: i.description, created: i.created, sizeGb: i.image_size, diskGb: i.disk_size };
}
