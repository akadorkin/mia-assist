import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { addKnownSecrets } from './output.js';

/**
 * Credentials mia uses to manage things beyond ssh: the panel, the Tailscale and Cloudflare APIs,
 * Gitea, Beszel. They live in ~/.config/mia/secrets.env (mode 600, never in git) or in the
 * environment; a value may be a 1Password reference (op://vault/item/field), read with `op read`.
 * Values are never printed: every known value is masked in all output.
 */
export interface SecretSpec {
    name: string;
    /** false: a setting (URL, name, path), shown in `mia secrets`. */
    secret: boolean;
    about: string;
    usedFor: string;
    group: string;
    /** Most fleets do without it: the setup walk-through skips it unless it is set. */
    optional?: boolean;
    /** Why a value cannot be right (op:// references are not checked). */
    validate?: (v: string) => string | undefined;
}

const url = (v: string) => (/^https?:\/\/[^\s/]+/.test(v) ? undefined : 'нужен адрес вида https://host[:порт]');
const prefix = (p: string, what: string) => (v: string) => (v.startsWith(p) ? undefined : `${what} начинается с ${p}`);

/** Groups in the order the setup walks them. */
export const SECRET_GROUPS: Array<{ id: string; title: string }> = [
    { id: 'панель', title: 'Панель Remnawave' },
    { id: 'tailscale', title: 'Tailscale' },
    { id: 'cloudflare', title: 'Cloudflare (DNS)' },
    { id: 'gitea', title: 'Gitea (раннеры)' },
    { id: 'beszel', title: 'Beszel (мониторинг)' },
    { id: 'медиа', title: 'Jellyfin и Tdarr' },
    { id: 'mia', title: 'mia: инвентарь, репозитории, mcp-remnawave, ssh' },
];

export const SECRETS: SecretSpec[] = [
    { group: 'панель', name: 'REMNAWAVE_BASE_URL', secret: false, about: 'адрес панели, https://panel.example.com', usedFor: 'состояние нод в статусе и аудите, SECRET_KEY для новых нод', validate: url },
    { group: 'панель', name: 'REMNAWAVE_API_TOKEN', secret: true, about: 'API-токен панели (Настройки → API-токены)', usedFor: 'то же' },
    { group: 'панель', name: 'REMNAWAVE_API_KEY', secret: true, optional: true, about: 'X-Api-Key, если панель закрыта им', usedFor: 'доступ к API панели' },
    { group: 'панель', name: 'CF_ACCESS_CLIENT_ID', secret: false, optional: true, about: 'Cloudflare Access: client id, если панель за Access', usedFor: 'доступ к API панели' },
    { group: 'панель', name: 'CF_ACCESS_CLIENT_SECRET', secret: true, optional: true, about: 'Cloudflare Access: client secret', usedFor: 'то же' },
    { group: 'tailscale', name: 'TAILSCALE_API_KEY', secret: true, about: 'tskey-api-… (админка → Settings → Keys)', usedFor: 'все устройства tailnet: в сети, ключи, обновления; удаление машины', validate: prefix('tskey-', 'ключ Tailscale') },
    { group: 'tailscale', name: 'TAILSCALE_TAILNET', secret: false, optional: true, about: 'имя tailnet; по умолчанию «-» — tailnet ключа', usedFor: 'Tailscale API' },
    { group: 'tailscale', name: 'TAILSCALE_AUTH_KEY', secret: true, about: 'tskey-auth-… (многоразовый, pre-approved)', usedFor: 'новые ноды входят в tailnet без ссылки для входа', validate: prefix('tskey-auth-', 'ключ входа') },
    { group: 'cloudflare', name: 'CLOUDFLARE_API_TOKEN', secret: true, about: 'токен с Zone:DNS:Edit (+ Zone:Read) на зоны флота', usedFor: 'DNS-записи: новые ноды, перенос ингресса, вывод' },
    { group: 'gitea', name: 'GITEA_URL', secret: false, about: 'адрес Gitea, доступный с этой машины', usedFor: 'раннеры', validate: url },
    { group: 'gitea', name: 'GITEA_TOKEN', secret: true, about: 'токен доступа Gitea (админ, для раннеров)', usedFor: 'регистрация, список и удаление раннеров' },
    { group: 'beszel', name: 'BESZEL_URL', secret: false, about: 'адрес хаба Beszel', usedFor: 'карточки мониторинга', validate: url },
    { group: 'beszel', name: 'BESZEL_EMAIL', secret: false, about: 'логин администратора Beszel', usedFor: 'то же' },
    { group: 'beszel', name: 'BESZEL_PASSWORD', secret: true, about: 'пароль администратора Beszel', usedFor: 'то же' },
    { group: 'медиа', name: 'JELLYFIN_API_KEY', secret: true, optional: true, about: 'Jellyfin → Панель → API-ключи (в fleet.yaml: apiKey: env:JELLYFIN_API_KEY)', usedFor: 'jellyfin_status и библиотеки' },
    { group: 'медиа', name: 'TDARR_API_KEY', secret: true, optional: true, about: 'только если в Tdarr включена авторизация (apiKey: env:TDARR_API_KEY)', usedFor: 'tdarr_status и библиотеки' },
    {
        group: 'mia',
        name: 'MIA_INVENTORY',
        secret: false,
        about: 'путь к fleet.yaml, например ~/mia-inventory/fleet.yaml (по умолчанию ~/.config/mia/fleet.yaml)',
        usedFor: 'список хостов',
        validate: (v) => (/\.ya?ml$/.test(v) ? undefined : 'нужен путь к .yaml'),
    },
    {
        group: 'mia',
        name: 'MIA_REPOS',
        secret: false,
        about: 'клоны репозиториев: ops=~/ops-scripts,haproxy=~/haproxy-configs',
        usedFor: 'repo_script, gitea_runner_register, local-шаги ранбуков',
        validate: (v) => (v.split(',').every((p) => /^\s*[\w-]+\s*=\s*\S/.test(p)) ? undefined : 'формат: имя=путь,имя=путь'),
    },
    {
        group: 'mia',
        name: 'MIA_GIT_AUTHOR',
        secret: false,
        optional: true,
        about: 'автор коммитов ранбуков: Имя <почта>',
        usedFor: 'коммиты в haproxy-configs и ops-scripts из сценариев (клон без user.name коммитить отказывается)',
        validate: (v) => (/^.+\s*<[^<>\s]+@[^<>\s]+>$/.test(v.trim()) ? undefined : 'формат: Имя <почта>'),
    },
    { group: 'mia', name: 'MIA_REMNAWAVE_MCP', secret: false, about: 'команда запуска mcp-remnawave, например node ~/mcp-remnawave/dist/index.js', usedFor: 'шаги ранбуков в панели' },
    { group: 'mia', name: 'MIA_SSH_OPTIONS', secret: false, optional: true, about: 'доп. опции ssh, например -o ProxyJump=bastion', usedFor: 'все подключения' },
    { group: 'mia', name: 'MIA_TAILSCALE_BIN', secret: false, optional: true, about: 'tailscale из App Store: /Applications/Tailscale.app/Contents/MacOS/Tailscale', usedFor: 'статус tailnet без API-ключа' },
];

export function secretsFile(env: NodeJS.ProcessEnv = process.env): string {
    return env.MIA_SECRETS_FILE || path.join(env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'mia', 'secrets.env');
}

/** KEY=value lines; # comments; optional single or double quotes. */
export function parseEnvFile(text: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
        if (!m) continue;
        let v = m[2].trim();
        if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) v = v.slice(1, -1);
        out.set(m[1], v);
    }
    return out;
}

export interface SecretState {
    name: string;
    source: 'env' | 'file' | '1password' | 'missing';
    error?: string;
}

/**
 * Load the secrets file into the environment (variables already set win), resolving op:// references.
 * Returns where each known name came from. Loose file permissions are reported, not fixed silently.
 */
export function loadSecrets(env: NodeJS.ProcessEnv = process.env): { file: string; states: SecretState[]; warning?: string } {
    const file = secretsFile(env);
    const fromEnv = new Set(Object.keys(env).filter((k) => env[k]));
    const states = new Map<string, SecretState>();
    let warning: string | undefined;
    if (fs.existsSync(file)) {
        const mode = fs.statSync(file).mode & 0o777;
        if (mode & 0o077) warning = `${file} доступен другим пользователям (права ${mode.toString(8)}): chmod 600 ${file}`;
        for (const [k, v] of parseEnvFile(fs.readFileSync(file, 'utf8'))) {
            if (fromEnv.has(k)) continue;
            if (v.startsWith('op://')) {
                try {
                    env[k] = execFileSync('op', ['read', '--no-newline', v], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 });
                    states.set(k, { name: k, source: '1password' });
                } catch (e) {
                    states.set(k, { name: k, source: 'missing', error: `op read не сработал: ${(e as Error).message.split('\n')[0]}` });
                }
            } else {
                env[k] = v;
                states.set(k, { name: k, source: 'file' });
            }
        }
    }
    for (const s of SECRETS) if (!states.has(s.name)) states.set(s.name, { name: s.name, source: env[s.name] ? 'env' : 'missing' });
    addKnownSecrets(SECRETS.filter((s) => s.secret).map((s) => env[s.name]));
    return { file, states: [...states.values()], warning };
}

/** Set or remove one KEY in the secrets file, keeping the other lines; the file stays 600. */
export function writeSecret(name: string, value: string | undefined, env: NodeJS.ProcessEnv = process.env): string {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`плохое имя ${name}`);
    if (value !== undefined && /[\n\r]/.test(value)) throw new Error('в значении перевод строки');
    const file = secretsFile(env);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const lines = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n') : ['# ключи mia: ИМЯ=значение или ИМЯ=op://vault/item/field. Никогда не коммитить.'];
    const re = new RegExp(`^\\s*(?:export\\s+)?${name}\\s*=`);
    if (value !== undefined && value.includes("'") && value.includes('"')) throw new Error('в значении оба вида кавычек');
    const quoted = value === undefined ? '' : /^[\w@%+=:,./~-]*$/.test(value) ? value : value.includes("'") ? `"${value}"` : `'${value}'`;
    const i = lines.findIndex((l) => re.test(l));
    if (value === undefined) {
        if (i >= 0) lines.splice(i, 1);
    } else if (i >= 0) lines[i] = `${name}=${quoted}`;
    else {
        while (lines.length && lines[lines.length - 1] === '') lines.pop();
        lines.push(`${name}=${quoted}`);
    }
    fs.writeFileSync(file, lines.join('\n').replace(/\n*$/, '\n'), { mode: 0o600 });
    fs.chmodSync(file, 0o600);
    return file;
}
