import { spawn } from 'node:child_process';
import os from 'node:os';
import { keyDaysLeft, tsDevices } from './tailscale.js';
import { Config, PanelConfig } from '../config.js';
import { Host } from './inventory.js';

/** The fields of a panel node this server looks at. */
export interface PanelNode {
    uuid: string;
    name: string;
    address: string;
    port?: number;
    isConnected?: boolean;
    isConnecting?: boolean;
    isDisabled?: boolean;
    usersOnline?: number;
    lastStatusMessage?: string | null;
    xrayUptime?: number | string;
    versions?: { xray?: string; node?: string } | null;
    countryCode?: string;
    tags?: string[];
}

/**
 * Minimal read-only view of the Remnawave panel. Everything that changes the panel
 * belongs to mcp-remnawave; here the panel only answers "which node is this host,
 * is it connected, how many users would a reboot kick" and hands out a SECRET_KEY
 * for a new node.
 */
export class Panel {
    private cache?: { at: number; nodes: PanelNode[] };

    constructor(private cfg: PanelConfig) {}

    private headers(): Record<string, string> {
        const h: Record<string, string> = { Authorization: `Bearer ${this.cfg.apiToken}`, Accept: 'application/json' };
        if (this.cfg.apiKey) h['X-Api-Key'] = this.cfg.apiKey;
        if (this.cfg.cfAccessClientId) h['CF-Access-Client-Id'] = this.cfg.cfAccessClientId;
        if (this.cfg.cfAccessClientSecret) h['CF-Access-Client-Secret'] = this.cfg.cfAccessClientSecret;
        return h;
    }

    private async get<T>(p: string): Promise<T> {
        const res = await fetch(this.cfg.baseUrl + p, { headers: this.headers(), signal: AbortSignal.timeout(20_000) });
        const text = await res.text();
        if (!res.ok) throw new Error(`panel ${res.status} GET ${p}: ${text.slice(0, 300)}`);
        const body = JSON.parse(text) as { response: T };
        return body.response;
    }

    async nodes(fresh = false): Promise<PanelNode[]> {
        if (!fresh && this.cache && Date.now() - this.cache.at < 30_000) return this.cache.nodes;
        const nodes = await this.get<PanelNode[]>('/api/nodes/');
        this.cache = { at: Date.now(), nodes };
        return nodes;
    }

    /** A fresh SECRET_KEY for a node's docker-compose (panel → Nodes → create). */
    async secretKey(): Promise<string> {
        const r = await this.get<{ secretKey: string }>('/api/keygen/');
        return r.secretKey;
    }
}

export function panelOf(config: Config): Panel | undefined {
    return config.panel ? new Panel(config.panel) : undefined;
}

/** Which panel node is this host: explicit panelNode, else the node whose address is the host's domain/address/name. */
export function matchNode(host: Host, nodes: PanelNode[]): PanelNode | undefined {
    const lc = (s?: string) => (s ?? '').toLowerCase();
    if (host.panelNode) return nodes.find((n) => lc(n.name) === lc(host.panelNode) || n.uuid === host.panelNode);
    const keys = new Set([host.domain, host.address, host.name, host.bootstrap?.address].filter(Boolean).map(lc));
    return nodes.find((n) => keys.has(lc(n.address))) ?? nodes.find((n) => lc(n.name) === lc(host.name));
}

export function nodeState(n: PanelNode): string {
    return n.isDisabled ? 'disabled' : n.isConnected ? 'connected' : n.isConnecting ? 'connecting' : 'DISCONNECTED';
}

// ------------------------------------------------------------------ Tailscale

export interface TailscalePeer {
    hostName: string;
    dnsName: string;
    ips: string[];
    online: boolean;
    lastSeen?: string;
    os?: string;
    exitNode?: boolean;
    self?: boolean;
    /** From the Tailscale API only. */
    id?: string;
    keyDaysLeft?: number;
    updateAvailable?: boolean;
    clientVersion?: string;
    tags?: string[];
    user?: string;
}

/**
 * A person's own device (phone, tablet, laptop, desktop): never a fleet host, so it is not reported as
 * «missing from fleet.yaml». Tailscale reports iPads as iOS; tvOS covers Apple TV.
 */
export function isPersonalDevice(p: Pick<TailscalePeer, 'os'>): boolean {
    return /^(macos|ios|ipados|tvos|android|windows)$/i.test((p.os ?? '').trim());
}

/**
 * Devices of the tailnet: through the Tailscale API when TAILSCALE_API_KEY is set (every device,
 * key expiry, updates), else `tailscale status --json` on this machine.
 */
export async function tailscalePeers(config: Config): Promise<TailscalePeer[]> {
    if (config.tailscaleApi) {
        const me = os.hostname().toLowerCase().split('.')[0];
        return (await tsDevices(config.tailscaleApi)).map((d) => ({
            hostName: d.hostname,
            dnsName: (d.name ?? '').replace(/\.$/, ''),
            ips: d.addresses ?? [],
            online: d.connectedToControl ?? (d.lastSeen ? Date.now() - Date.parse(d.lastSeen) < 5 * 60_000 : false),
            lastSeen: d.lastSeen,
            os: d.os,
            self: d.hostname.toLowerCase().split('.')[0] === me || undefined,
            id: d.id,
            keyDaysLeft: keyDaysLeft(d),
            updateAvailable: d.updateAvailable,
            clientVersion: d.clientVersion?.split('-')[0],
            tags: d.tags,
            user: d.user,
        }));
    }
    const json = await new Promise<string>((resolve, reject) => {
        const child = spawn(config.tailscaleBin, ['status', '--json'], { stdio: ['ignore', 'pipe', 'pipe'] });
        let out = '';
        let err = '';
        child.stdout.on('data', (d) => (out += d));
        child.stderr.on('data', (d) => (err += d));
        child.on('error', (e) => reject(new Error(`не удалось запустить ${config.tailscaleBin}: ${e.message} (задайте MIA_TAILSCALE_BIN или TAILSCALE_API_KEY)`)));
        child.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`tailscale status не сработал: ${err.trim() || code}`))));
    });
    type Raw = { HostName: string; DNSName: string; TailscaleIPs?: string[]; Online?: boolean; LastSeen?: string; OS?: string; ExitNodeOption?: boolean };
    const st = JSON.parse(json) as { Self?: Raw; Peer?: Record<string, Raw> };
    const conv = (p: Raw, self = false): TailscalePeer => ({
        hostName: p.HostName,
        dnsName: (p.DNSName ?? '').replace(/\.$/, ''),
        ips: p.TailscaleIPs ?? [],
        online: self ? true : !!p.Online,
        lastSeen: p.LastSeen && !p.LastSeen.startsWith('0001') ? p.LastSeen : undefined,
        os: p.OS,
        exitNode: p.ExitNodeOption,
        self: self || undefined,
    });
    return [...(st.Self ? [conv(st.Self, true)] : []), ...Object.values(st.Peer ?? {}).map((p) => conv(p))];
}

export function matchPeer(host: Host, peers: TailscalePeer[]): TailscalePeer | undefined {
    const a = host.address.toLowerCase();
    return (
        peers.find((p) => p.dnsName.toLowerCase() === a || p.ips.includes(host.address)) ??
        peers.find((p) => p.dnsName.toLowerCase().split('.')[0] === a || p.hostName.toLowerCase() === a) ??
        peers.find((p) => p.hostName.toLowerCase() === host.name.toLowerCase())
    );
}
