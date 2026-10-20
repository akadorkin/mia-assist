import fs from 'node:fs';
import path from 'node:path';
import { Config } from './config.js';
import { why } from './core/neterr.js';
export { why };
import { Ctx } from './core/ctx.js';
import { SECRETS, SecretState, loadSecrets, secretsFile, writeSecret } from './core/secrets.js';
import { tsDevices } from './core/tailscale.js';

/** Read a line without echo (for secret values); plain line when stdin is not a terminal. */
export function askHidden(prompt: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const stdin = process.stdin;
        process.stdout.write(prompt);
        if (!stdin.isTTY) {
            let buf = '';
            stdin.setEncoding('utf8');
            stdin.on('data', (d) => (buf += d));
            stdin.on('end', () => resolve(buf.split('\n')[0]));
            return;
        }
        let value = '';
        stdin.setRawMode(true);
        stdin.resume();
        stdin.setEncoding('utf8');
        const onData = (ch: string) => {
            for (const c of ch) {
                if (c === '\r' || c === '\n') {
                    stdin.setRawMode(false);
                    stdin.pause();
                    stdin.off('data', onData);
                    process.stdout.write('\n');
                    return resolve(value);
                }
                if (c === '\u0003') {
                    stdin.setRawMode(false);
                    stdin.off('data', onData);
                    process.stdout.write('\n');
                    return reject(new Error('отменено'));
                }
                if (c === '\u007f' || c === '\b') value = value.slice(0, -1);
                else value += c;
            }
        };
        stdin.on('data', onData);
    });
}

export function secretsTable(states: SecretState[]): Array<Record<string, string>> {
    return SECRETS.map((s) => {
        const st = states.find((x) => x.name === s.name);
        const src = { env: 'окружение', file: 'файл', '1password': '1Password', missing: '' }[st?.source ?? 'missing'];
        return { group: s.group, name: s.name, state: st?.source === 'missing' ? (st.error ? `ОШИБКА ${st.error}` : '—') : `ok, задан (${src})`, about: s.about };
    });
}

async function probe(label: string, fn: () => Promise<string>): Promise<Record<string, string>> {
    try {
        return { check: label, result: `ok: ${await fn()}` };
    } catch (e) {
        return { check: label, result: `ОШИБКА: ${why(e).slice(0, 160)}` };
    }
}

async function getJson(url: string, headers: Record<string, string>): Promise<any> {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(20_000) });
    const t = await r.text();
    if (!r.ok) throw new Error(`${r.status} ${t.slice(0, 120)}`);
    return JSON.parse(t);
}

/** Live check of every configured credential (or of some groups of SECRET_GROUPS); values are never printed. */
export async function checkSecrets(config: Config, ctx: Ctx, groups?: string[]): Promise<Array<Record<string, string>>> {
    const out: Array<Record<string, string>> = [];
    const want = (g: string) => !groups || groups.includes(g);
    const none = (what: string, extra = '') => ({ check: what, result: `не задано${extra}` });
    if (want('панель')) {
        if (ctx.panel) out.push(await probe('панель', async () => `${(await ctx.panel!.nodes(true)).length} нод`));
        else out.push(none('панель'));
    }
    if (want('tailscale')) {
        if (config.tailscaleApi) {
            out.push(
                await probe('tailscale api', async () => {
                    const d = await tsDevices(config.tailscaleApi!);
                    return `${d.length} устройств, ${d.filter((x) => x.connectedToControl).length} в сети`;
                }),
            );
        } else out.push(none('tailscale api', ' (используется локальный tailscale status)'));
        out.push({ check: 'tailscale auth key', result: process.env.TAILSCALE_AUTH_KEY ? 'ok, задан (проверится при входе новой ноды)' : 'не задано: новые ноды войдут по ссылке' });
    }
    if (want('cloudflare')) {
        if (config.cloudflareToken) {
            const h = { Authorization: `Bearer ${config.cloudflareToken}` };
            out.push(
                await probe('cloudflare', async () => {
                    const v = await getJson('https://api.cloudflare.com/client/v4/user/tokens/verify', h);
                    const z = await getJson('https://api.cloudflare.com/client/v4/zones?per_page=50', h);
                    return `токен ${v.result?.status}, зоны: ${(z.result ?? []).map((x: { name: string }) => x.name).join(', ') || 'нет'}`;
                }),
            );
        } else out.push(none('cloudflare'));
    }
    if (want('gitea')) {
        if (config.gitea) out.push(await probe('gitea', async () => `пользователь ${(await getJson(`${config.gitea!.url}/api/v1/user`, { Authorization: `token ${config.gitea!.token}` })).login}`));
        else out.push(none('gitea'));
    }
    if (want('beszel')) {
        if (config.beszel) {
            out.push(
                await probe('beszel', async () => {
                    const { beszelAuth } = await import('./core/beszel.js');
                    await beszelAuth(config.beszel!);
                    return 'вход ok';
                }),
            );
        } else out.push(none('beszel'));
    }
    if (want('медиа')) {
        const apps = [...ctx.inventory().hosts.values()].flatMap((h) => Object.entries(h.apps).map(([app, a]) => ({ host: h.name, app, key: a?.apiKey })));
        for (const a of apps) {
            const ref = a.key?.match(/^env:(\w+)$/)?.[1];
            out.push({ check: `${a.app} (${a.host})`, result: !a.key ? 'ключ не нужен (apiKey не задан в fleet.yaml)' : ref ? (process.env[ref] ? `ok, ${ref} задан` : `не задано: ${ref}`) : 'ok, ключ прямо в fleet.yaml' });
        }
        if (!apps.length) out.push({ check: 'медиа', result: 'в fleet.yaml нет apps.jellyfin / apps.tdarr' });
    }
    if (want('mia')) {
        out.push(
            await probe('инвентарь', async () => {
                if (!fs.existsSync(config.inventoryFile)) throw new Error(`нет файла ${config.inventoryFile}`);
                const inv = ctx.inventory();
                return `${inv.hosts.size} хостов, ${inv.groups.size} групп — ${config.inventoryFile}`;
            }),
        );
        const repos = Object.entries(config.repos);
        out.push({
            check: 'репозитории',
            result: !repos.length
                ? 'не задано (MIA_REPOS): ранбуки не смогут править ops-scripts и haproxy-configs'
                : repos.map(([k, v]) => `${k}: ${!fs.existsSync(v) ? `ОШИБКА нет ${v}` : fs.existsSync(path.join(v, '.git')) ? 'ok' : `ОШИБКА ${v} не git-клон`}`).join(', '),
        });
        out.push({ check: 'mcp-remnawave', result: config.remnawaveMcp ? `ok, команда задана (${config.remnawaveMcp.split(/\s+/)[0]} …)` : 'не задано (MIA_REMNAWAVE_MCP): шаги ранбуков в панели недоступны' });
    }
    return out;
}

export async function secretsCmd(rest: string[], deps: { config: () => Config; ctx: () => Ctx; table: (rows: Array<Record<string, unknown>>) => string }) {
    const [sub = 'list', name, ...more] = rest;
    if (sub === 'list') {
        const st = loadSecrets({ ...process.env });
        console.log(deps.table(secretsTable(st.states)));
        console.log(`\nфайл: ${secretsFile()}${st.warning ? `\n!! ${st.warning}` : ''}`);
        console.log('mia secrets set ИМЯ     спросит значение, не показывая его (или: mia secrets set ИМЯ op://vault/item/field)\nmia secrets check       проверить каждый ключ живым запросом');
        return;
    }
    if (sub === 'set') {
        if (!name) throw new Error('как: mia secrets set ИМЯ [op://…]');
        const spec = SECRETS.find((s) => s.name === name);
        if (!spec) console.log(`(${name} mia не знает — всё равно сохраняю)`);
        const value = more[0] ?? (await askHidden(`${name}${spec ? ` — ${spec.about}` : ''} (ввод не отображается): `));
        if (!value) throw new Error('пустое значение: ничего не сохранено');
        console.log(`сохранено в ${writeSecret(name, value)} (права 600)`);
        return;
    }
    if (sub === 'unset') {
        if (!name) throw new Error('как: mia secrets unset ИМЯ');
        console.log(`удалено из ${writeSecret(name, undefined)}`);
        return;
    }
    if (sub === 'check') {
        console.log(deps.table(await checkSecrets(deps.config(), deps.ctx())));
        return;
    }
    throw new Error('как: mia secrets [list | set ИМЯ | unset ИМЯ | check]');
}
