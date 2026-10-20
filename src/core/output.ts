import fs from 'node:fs';
import path from 'node:path';
import { Config } from '../config.js';

export type ToolResponse = {
    content: Array<{ type: 'text'; text: string }>;
    isError?: boolean;
};

export const REDACTED = '«redacted»';

/** Keys whose values never leave the server. */
const SECRET_KEYS = new Set(['secretKey', 'SECRET_KEY', 'privateKey', 'mldsa65Seed', 'password', 'apiToken', 'token', 'authKey']);

/**
 * Secrets that show up inside text: compose files, logs, command lines, xray configs.
 * Each pattern keeps its first group and masks the rest of the value.
 */
const SECRET_PATTERNS: RegExp[] = [
    /(SECRET_KEY\s*[=:]\s*["']?)[^\s"']+/g,
    /(--secret-key[= ]\s*["']?)[^\s"']+/g,
    /(secret_key=["']?)[^\s"']+/g,
    /("privateKey"\s*:\s*")[^"]+/g,
    /("mldsa65Seed"\s*:\s*")[^"]+/g,
    // env-style KEYS: DB_PASSWORD=…, BOT_TOKEN: …, WEBHOOK_SECRET=…
    /(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|SECRET)[A-Z0-9_]*\s*[=:]\s*["']?)[^\s"',&«]+/g,
    // yaml/json keys: password: …, "api_key": "…", db_password=… (not "ssh.password: …" prose)
    /((?<![.\w-])[\w-]*(?:password|passwd|token|secret|api_?key)"?\s*[:=]\s*["']?)[^\s"',&«]+/gi,
    /(tskey-(?:auth|api|client)-)[\w-]+/g,
    // proxy share links: the userinfo (VLESS/VMess UUID, Trojan/SS/Hysteria password) is the user's key
    /((?:vless|trojan|ss|hysteria2?|hy2|tuic|socks5?|anytls):\/\/)[^@\s'"`<>]{4,}(?=@)/gi,
    /(vmess:\/\/)[A-Za-z0-9+/=_-]{16,}/gi,
    // HTTP basic auth: curl -u 'user:pass', --user user:pass, Authorization: Basic …
    /((?:\s-u|--user)\s+["']?[^\s:"'$]+:)[^\s"']+/g,
    /(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]{8,}/gi,
    // Gitea/GitHub style: Authorization: token <hex>, ?token=<hex>, access_token=<hex>
    /(Authorization:\s*token\s+)[A-Za-z0-9_-]{20,}/gi,
    /([?&](?:access_)?token=)[A-Za-z0-9_-]{20,}/gi,
    /(sshpass\s+-p\s*["']?)[^\s"']+/g,
    // license keys like WARP+ (8-8-8, mixed case and digits; uuids are 8-4-4-4-12 and stay)
    /\b(?=[A-Za-z0-9-]*\d)(?=[A-Za-z0-9-]*[A-Z])[A-Za-z0-9]{8}-[A-Za-z0-9]{8}(?:-[A-Za-z0-9]{1,8})?\b-?/g,
    // subscription links: the short uuid is the subscription itself
    /(\/api\/sub\/)[A-Za-z0-9_-]{6,}/g,
    // credentials inside URLs: scheme://user:secret@host
    /(\b[a-z][\w+.-]*:\/\/[^:/\s@]+:)[^@\s]+(?=@)/gi,
    /(Authorization:\s*Bearer\s+)\S+/gi,
    // WireGuard/AmneziaWG: PrivateKey = … и PresharedKey = … (AUD-05)
    /((?:Private|Preshared)Key\s*=\s*)\S+/gi,
    // PEM-ключи целиком (ssh, TLS)
    /(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(?=-----END [A-Z ]*PRIVATE KEY-----)/g,
    // хеш пароля из /etc/shadow: user:$6$…
    /(^[\w.-]+:)\$[^:\s]+/gm,
    // "private_key": "…", private-key: …
    /((?<![.\w-])[\w-]*private[_-]?key"?\s*[:=]\s*["']?)[^\s"',&«]+/gi,
];

/** Exact values of the owner's configured secrets (secrets.env / env): masked wherever they appear. */
const KNOWN_SECRETS = new Set<string>();

export function addKnownSecrets(values: Iterable<string | undefined>) {
    for (const v of values) if (v && v.length >= 8) KNOWN_SECRETS.add(v);
}

export function redactText(s: string): string {
    let out = s;
    for (const v of KNOWN_SECRETS) if (out.includes(v)) out = out.split(v).join(REDACTED);
    for (const re of SECRET_PATTERNS) out = out.replace(re, (_m, g1) => `${typeof g1 === 'string' ? g1 : ''}${REDACTED}`);
    // a credential kept in a variable and used as `-u "$VAR"`: mask the assignment too
    for (const m of out.matchAll(/(?:\s-u|--user)\s+["']?\$\{?(\w+)\}?/g)) {
        const re = new RegExp(`(\\b${m[1]}=["']?[^\\s:"']+:)[^\\s"']+`, 'g');
        out = out.replace(re, `$1${REDACTED}`);
    }
    return out;
}

export function redact<T>(data: T): T {
    const walk = (v: unknown): unknown => {
        if (typeof v === 'string') return redactText(v);
        if (Array.isArray(v)) return v.map(walk);
        if (v && typeof v === 'object') {
            const out: Record<string, unknown> = {};
            for (const [k, val] of Object.entries(v)) {
                out[k] = SECRET_KEYS.has(k) && val !== null && val !== '' && val !== undefined && typeof val !== 'boolean' ? REDACTED : walk(val);
            }
            return out;
        }
        return v;
    };
    return walk(data) as T;
}

/**
 * Output policy shared by every tool:
 *  - secrets (remnanode SECRET_KEY, REALITY keys, tokens) are masked everywhere;
 *  - anything larger than maxOutputChars goes to a file under stateDir/out and the
 *    tool returns a summary plus the path.
 */
export class Output {
    private outDir: string;

    constructor(private config: Config) {
        this.outDir = path.join(config.stateDir, 'out');
    }

    save(label: string, data: unknown, ext = 'json'): string {
        fs.mkdirSync(this.outDir, { recursive: true, mode: 0o700 });
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        const file = path.join(this.outDir, `${label.replace(/[^\w.-]+/g, '_')}-${stamp}.${ext}`);
        fs.writeFileSync(file, typeof data === 'string' ? data : JSON.stringify(data, null, 2), { mode: 0o600 });
        return file;
    }

    ok(label: string, data: unknown): ToolResponse {
        const safe = redact(data ?? { success: true });
        let text = JSON.stringify(safe);
        if (text.length <= this.config.maxOutputChars) {
            if (text.length < 6000) text = JSON.stringify(safe, null, 1);
            return { content: [{ type: 'text', text }] };
        }
        const file = this.save(label, safe);
        const summary = {
            truncated: true,
            reason: `result is ${text.length} chars (limit ${this.config.maxOutputChars}); full JSON saved to a file`,
            savedTo: file,
            hint: 'Read or jq the file for details, or call again with a narrower target / filter.',
            shape: describe(safe),
        };
        return { content: [{ type: 'text', text: JSON.stringify(summary, null, 1) }] };
    }

    error(e: unknown): ToolResponse {
        const message = e instanceof Error ? e.message : String(e);
        return { content: [{ type: 'text', text: `Error: ${redactText(message)}` }], isError: true };
    }

    async run(label: string, fn: () => Promise<unknown>): Promise<ToolResponse> {
        try {
            return this.ok(label, await fn());
        } catch (e) {
            return this.error(e);
        }
    }
}

function describe(v: unknown, depth = 0): unknown {
    if (Array.isArray(v)) return depth > 2 ? `array(${v.length})` : { array: v.length, item: v.length ? describe(v[0], depth + 1) : null };
    if (v && typeof v === 'object') {
        if (depth > 2) return 'object';
        const out: Record<string, unknown> = {};
        for (const [k, val] of Object.entries(v).slice(0, 40)) out[k] = describe(val, depth + 1);
        return out;
    }
    return typeof v;
}
