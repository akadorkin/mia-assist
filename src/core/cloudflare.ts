/** Cloudflare DNS API (token with Zone:Read + DNS:Edit): the fleet's A records. */
const API = 'https://api.cloudflare.com/client/v4';

export interface Zone {
    id: string;
    name: string;
}

export interface DnsRecord {
    id: string;
    zoneId: string;
    zone: string;
    name: string;
    type: string;
    content: string;
    proxied: boolean;
    ttl: number;
}

async function cf<T>(token: string, method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${API}${path}`, {
        method,
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(30_000),
    });
    const j = (await res.json().catch(() => ({}))) as { success?: boolean; result?: T; errors?: Array<{ message: string }> };
    if (!res.ok || j.success === false) throw new Error(`Cloudflare ${method} ${path.split('?')[0]}: ${res.status} ${(j.errors ?? []).map((e) => e.message).join('; ')}`);
    return j.result as T;
}

export async function cfZones(token: string): Promise<Zone[]> {
    return (await cf<Array<{ id: string; name: string }>>(token, 'GET', '/zones?per_page=50')).map((z) => ({ id: z.id, name: z.name }));
}

/** The zone a name lives in: the longest zone name that is a suffix of it. */
export function zoneFor(zones: Zone[], name: string): Zone | undefined {
    const n = name.toLowerCase().replace(/\.$/, '');
    return zones.filter((z) => n === z.name || n.endsWith(`.${z.name}`)).sort((a, b) => b.name.length - a.name.length)[0];
}

const conv = (z: Zone, r: { id: string; name: string; type: string; content: string; proxied?: boolean; ttl: number }): DnsRecord => ({
    id: r.id,
    zoneId: z.id,
    zone: z.name,
    name: r.name,
    type: r.type,
    content: r.content,
    proxied: !!r.proxied,
    ttl: r.ttl,
});

/** Records by exact name (in its zone) and/or by content (an IP) across every zone the token sees. */
export async function cfRecords(token: string, q: { name?: string; content?: string; type?: string }, zones?: Zone[]): Promise<DnsRecord[]> {
    zones ??= await cfZones(token);
    const targets = q.name ? [zoneFor(zones, q.name)].filter((z): z is Zone => !!z) : zones;
    if (q.name && !targets.length) throw new Error(`no Cloudflare zone for ${q.name} (zones: ${zones.map((z) => z.name).join(', ')})`);
    const out: DnsRecord[] = [];
    for (const z of targets) {
        const params = new URLSearchParams({ per_page: '500' });
        if (q.name) params.set('name', q.name.toLowerCase());
        if (q.content) params.set('content', q.content);
        if (q.type) params.set('type', q.type);
        for (const r of await cf<Array<{ id: string; name: string; type: string; content: string; proxied?: boolean; ttl: number }>>(token, 'GET', `/zones/${z.id}/dns_records?${params}`)) out.push(conv(z, r));
    }
    return out;
}

export async function cfCreate(token: string, zone: Zone, rec: { type: string; name: string; content: string; proxied?: boolean; ttl?: number }): Promise<DnsRecord> {
    return conv(zone, await cf(token, 'POST', `/zones/${zone.id}/dns_records`, { ttl: 1, proxied: false, ...rec }));
}

export async function cfUpdate(token: string, r: DnsRecord, patch: { content?: string; proxied?: boolean; ttl?: number }): Promise<DnsRecord> {
    return conv({ id: r.zoneId, name: r.zone }, await cf(token, 'PATCH', `/zones/${r.zoneId}/dns_records/${r.id}`, patch));
}

export async function cfDelete(token: string, r: DnsRecord): Promise<void> {
    await cf(token, 'DELETE', `/zones/${r.zoneId}/dns_records/${r.id}`);
}
