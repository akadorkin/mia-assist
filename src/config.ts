import os from 'node:os';
import path from 'node:path';

export interface PanelConfig {
    baseUrl: string;
    apiToken: string;
    apiKey?: string;
    cfAccessClientId?: string;
    cfAccessClientSecret?: string;
}

export interface Config {
    /** Path of the inventory (fleet.yaml). */
    inventoryFile: string;
    /** true = only tools that do not change hosts. */
    readonly: boolean;
    /** Journal, snapshots, oversized outputs, bootstrap logs. */
    stateDir: string;
    /** Tool output larger than this many characters is written to a file instead. */
    maxOutputChars: number;
    /** ssh binary; the system one, so ~/.ssh/config, the agent and Tailscale SSH all work as in a terminal. */
    sshBin: string;
    /** Extra options for every ssh call (split on spaces). */
    sshOptions: string[];
    /** Reuse one ssh connection per host for 2 minutes (ControlMaster): plan → apply → logs without new handshakes. */
    sshReuse: boolean;
    /** How long probed facts serve plans and reads (status / audit always probe afresh), ms. */
    factsTtlMs: number;
    /** Waits for hosts to come back are multiplied by this (1; the demo fleet shortens them). */
    timeScale: number;
    /** A made-up fleet, nothing leaves this machine (mia --demo). */
    demo?: boolean;
    /** Connect timeout, seconds. */
    sshConnectTimeout: number;
    /** Default timeout of one remote command, ms. */
    commandTimeoutMs: number;
    /** How many hosts are talked to at once. */
    concurrency: number;
    tailscaleBin: string;
    /** Remnawave panel, read-only use (node cross-check, secret keys for bootstrap). */
    panel?: PanelConfig;
    /** Raw URLs of the bootstrap/tuning scripts, pinned here so a run is reproducible. */
    edgeScriptUrl: string;
    tuningScriptUrl: string;
    /** Local checkouts of your fleet script repos (MIA_REPOS="ops=~/src/ops-scripts,haproxy=~/src/haproxy-configs"). */
    repos: Record<string, string>;
    /** Command that starts mcp-remnawave for panel steps of scenarios (MIA_REMNAWAVE_MCP). */
    remnawaveMcp?: string;
    /** Tailscale API (every device, key expiry, removal); without it the local `tailscale status` is used. */
    tailscaleApi?: { key: string; tailnet: string };
    cloudflareToken?: string;
    gitea?: { url: string; token: string };
    beszel?: { url: string; email: string; password: string };
    /** Author of the commits scenarios make in your repos (MIA_GIT_AUTHOR="Name <email>"): a checkout without user.name refuses to commit. */
    gitAuthor?: { name: string; email: string };
}

/** "Name <email>" → {name, email}; anything else → undefined. */
export function parseAuthor(raw: string | undefined): { name: string; email: string } | undefined {
    const m = (raw ?? '').trim().match(/^(.+?)\s*<([^<>\s]+@[^<>\s]+)>$/);
    return m ? { name: m[1], email: m[2] } : undefined;
}

/** "name=path,name=path" → {name: absolute path}; ~ is the home directory. */
export function parseRepos(raw: string | undefined): Record<string, string> {
    const out: Record<string, string> = {};
    for (const part of (raw ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
        const i = part.indexOf('=');
        if (i <= 0) throw new Error(`MIA_REPOS: "${part}" is not name=path`);
        const p = part.slice(i + 1).trim();
        out[part.slice(0, i).trim()] = path.resolve(p.startsWith('~/') ? path.join(os.homedir(), p.slice(2)) : p);
    }
    return out;
}

export const DEFAULT_EDGE_SCRIPT =
    'https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh';
// a commit, not a branch: a push to main must not become root code on the fleet 
export const DEFAULT_TUNING_SCRIPT = 'https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/4bb5d3a465bc1a4678fd104696852c02e5a88560/initial.sh';

/** ~/x → absolute: values from secrets.env are not expanded by a shell. */
const home = (p: string | undefined) => (p?.startsWith('~/') ? path.join(os.homedir(), p.slice(2)) : p);

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
    const stateHome = env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state');
    const configHome = env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');

    const baseUrl = env.REMNAWAVE_BASE_URL?.replace(/\/+$/, '');
    const apiToken = env.REMNAWAVE_API_TOKEN;

    return {
        inventoryFile: home(env.MIA_INVENTORY) || path.join(configHome, 'mia', 'fleet.yaml'),
        readonly: env.MIA_READONLY === 'true',
        stateDir: home(env.MIA_STATE_DIR) || path.join(stateHome, 'mia'),
        maxOutputChars: Number(env.MIA_MAX_OUTPUT_CHARS) || 40000,
        sshBin: env.MIA_SSH_BIN || 'ssh',
        sshOptions: (env.MIA_SSH_OPTIONS || '').split(/\s+/).filter(Boolean),
        sshReuse: env.MIA_SSH_REUSE !== '0',
        timeScale: Number(env.MIA_TIME_SCALE) > 0 ? Number(env.MIA_TIME_SCALE) : 1,
        factsTtlMs: (Number(env.MIA_FACTS_TTL) >= 0 && env.MIA_FACTS_TTL !== undefined && env.MIA_FACTS_TTL !== '' ? Number(env.MIA_FACTS_TTL) : 120) * 1000,
        sshConnectTimeout: Number(env.MIA_SSH_CONNECT_TIMEOUT) || 10,
        commandTimeoutMs: Number(env.MIA_COMMAND_TIMEOUT_MS) || 120_000,
        concurrency: Math.max(1, Number(env.MIA_CONCURRENCY) || 4),
        tailscaleBin: env.MIA_TAILSCALE_BIN || 'tailscale',
        repos: parseRepos(env.MIA_REPOS),
        remnawaveMcp: env.MIA_REMNAWAVE_MCP?.trim() || undefined,
        tailscaleApi: env.TAILSCALE_API_KEY ? { key: env.TAILSCALE_API_KEY, tailnet: env.TAILSCALE_TAILNET || '-' } : undefined,
        cloudflareToken: env.CLOUDFLARE_API_TOKEN || undefined,
        gitea: env.GITEA_URL && env.GITEA_TOKEN ? { url: env.GITEA_URL.replace(/\/+$/, ''), token: env.GITEA_TOKEN } : undefined,
        gitAuthor: parseAuthor(env.MIA_GIT_AUTHOR),
        beszel: env.BESZEL_URL && env.BESZEL_EMAIL && env.BESZEL_PASSWORD ? { url: env.BESZEL_URL.replace(/\/+$/, ''), email: env.BESZEL_EMAIL, password: env.BESZEL_PASSWORD } : undefined,
        panel:
            baseUrl && apiToken
                ? {
                      baseUrl,
                      apiToken,
                      apiKey: env.REMNAWAVE_API_KEY,
                      cfAccessClientId: env.CF_ACCESS_CLIENT_ID,
                      cfAccessClientSecret: env.CF_ACCESS_CLIENT_SECRET,
                  }
                : undefined,
        edgeScriptUrl: env.MIA_EDGE_SCRIPT_URL || DEFAULT_EDGE_SCRIPT,
        tuningScriptUrl: env.MIA_TUNING_SCRIPT_URL || DEFAULT_TUNING_SCRIPT,
    };
}
