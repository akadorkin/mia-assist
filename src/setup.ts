import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { parseDocument } from 'yaml';
import { c } from './color.js';
import { Config, loadConfig } from './config.js';
import { Ctx } from './core/ctx.js';
import { HostEdit, HostField, planFleet, readFleet, writeFleet } from './core/fleetfile.js';
import { ROLES, adhocHost } from './core/inventory.js';
import { TailscalePeer, isPersonalDevice, matchPeer, tailscalePeers } from './core/panel.js';
import { SECRETS, SECRET_GROUPS, SecretSpec, loadSecrets, secretsFile, writeSecret } from './core/secrets.js';
import { Choice, PickOpts } from './select.js';
import { checkSecrets } from './secrets-cli.js';
import { table } from './ui.js';

/** What the setup needs from the console: questions, menus, yes/no (Enter — да). */
export interface Io {
    ask(q: string, opts?: { initial?: string }): Promise<string>;
    askSecret(q: string): Promise<string>;
    choose(title: string, items: Choice[], opts?: PickOpts): Promise<number | undefined>;
    chooseMany(title: string, items: Choice[], checked: number[]): Promise<number[] | undefined>;
    confirm(q: string): Promise<boolean>;
}

export interface Env {
    config: Config;
    ctx: Ctx;
}

const ROLE_RU: Record<string, string> = {
    edge: 'сервер из vps-edge-run.sh (ufw, fail2ban, MGMT-PORTS, blacklist)',
    remnanode: 'нода Remnawave (включает edge)',
    panel: 'хост панели',
    docker: 'docker-сервисы (дом, боты)',
};

const section = (t: string) => console.log(`\n${c.bold(c.cyan(`◆ ${t}`))}`);
const ok = (t: string) => console.log(`  ${c.green('✔')} ${t}`);
const bad = (t: string) => console.log(`  ${c.red('✖')} ${t}`);
const note = (t: string) => console.log(c.gray(`  ${t}`));

// ------------------------------------------------------------------ keys and addresses

function stateOf(spec: SecretSpec): { set: boolean; label: string; fromShell: boolean } {
    const st = loadSecrets({ ...process.env }).states.find((s) => s.name === spec.name);
    const src = st?.source ?? 'missing';
    if (src === 'missing') return { set: false, label: st?.error ? c.red(`ошибка: ${st.error}`) : c.yellow('не задан'), fromShell: false };
    const where = { env: 'окружение терминала', file: 'файл', '1password': '1Password' }[src];
    const value = !spec.secret && process.env[spec.name] ? `${process.env[spec.name]}` : 'задан';
    return { set: true, label: `${c.green(value)} ${c.gray(`(${where})`)}`, fromShell: src === 'env' };
}

/** Save one key to secrets.env and make it effective in this session (panel client included). */
export function saveSetting(env: Env, name: string, value: string | undefined): string {
    const file = writeSecret(name, value);
    delete process.env[name];
    loadSecrets(); // the file is the source now (op:// resolved)
    Object.assign(env.config, loadConfig());
    env.ctx.reconfigure();
    return file;
}

/**
 * Ask one key. Secrets are typed blind: Enter keeps, «-» clears. Plain settings come prefilled:
 * edit in place, Enter saves, an emptied line clears. Returns true when something was saved.
 */
async function askSetting(io: Io, env: Env, spec: SecretSpec): Promise<boolean> {
    const st = stateOf(spec);
    console.log(`  ${c.bold(spec.name)} ${c.gray('—')} ${spec.about}`);
    console.log(`    ${c.gray('сейчас:')} ${st.label}`);
    if (st.fromShell) note('  задан в окружении терминала — он главнее файла; чтобы менять здесь, уберите export из ~/.zshrc');
    for (;;) {
        let raw: string;
        if (spec.secret) raw = (await io.askSecret(`    ${c.gray(st.set ? 'новое значение (скрыто; Enter — оставить, «-» — очистить, можно op://…):' : 'значение (скрыто; Enter — пропустить, можно op://…):')} `)).trim();
        else {
            raw = (await io.ask(`    ${c.gray('›')} `, { initial: process.env[spec.name] ?? '' })).trim();
            if (raw === (process.env[spec.name] ?? '')) return false;
            if (!raw) raw = '-';
        }
        if (!raw) return false;
        if (raw === '-') {
            if (!st.set) return false;
            saveSetting(env, spec.name, undefined);
            ok(`${spec.name} очищен`);
            return true;
        }
        const err = raw.startsWith('op://') ? undefined : spec.validate?.(raw);
        if (err) {
            bad(err);
            continue;
        }
        saveSetting(env, spec.name, raw);
        ok(`${spec.name} сохранён ${c.gray(`в ${secretsFile()}`)}`);
        return true;
    }
}

async function showChecks(env: Env, groups?: string[]) {
    process.stdout.write(c.gray('  … проверяю живыми запросами\n'));
    for (const r of await checkSecrets(env.config, env.ctx, groups)) {
        const good = /^ok/.test(r.result);
        const off = /^не задано|не нужен|нет apps/.test(r.result);
        console.log(`  ${good ? c.green('✔') : off ? c.gray('○') : c.red('✖')} ${r.check.padEnd(16)} ${good ? r.result.replace(/^ok[:,]?\s*/, '') : off ? c.gray(r.result) : c.red(r.result)}`);
    }
}

/** Every key and address, group by group; then the hosts. */
export async function setupWizard(io: Io, env: Env) {
    console.log(`\n${c.bold('Настройка по порядку')}  ${c.gray(`ключи → ${secretsFile()} (600), значения не показываются`)}`);
    note('Enter — оставить как есть · у скрытых «-» — очистить · Ctrl+C — выйти (сохранённое остаётся)');
    for (const g of SECRET_GROUPS) {
        const specs = SECRETS.filter((s) => s.group === g.id && (!s.optional || stateOf(s).set));
        const extra = SECRETS.filter((s) => s.group === g.id && s.optional && !stateOf(s).set);
        section(g.title);
        let changed = false;
        for (const s of specs) changed = (await askSetting(io, env, s)) || changed;
        if (extra.length) note(`ещё, если нужно: ${extra.map((s) => s.name).join(', ')} — пункт «Ключи и адреса»`);
        if (changed) await showChecks(env, [g.id]);
    }
    section('Хосты');
    await hostsSummary(io, env, true);
}

/** One key from the full list (optional ones included). */
export async function editSettings(io: Io, env: Env) {
    for (;;) {
        const items = SECRETS.map((s) => {
            const st = stateOf(s);
            return { label: `${s.name.padEnd(24)} ${st.set ? c.green('●') : s.optional ? c.gray('○') : c.yellow('○')}`, hint: `${SECRET_GROUPS.find((g) => g.id === s.group)?.title ?? s.group} — ${s.about}`, keys: s.group };
        });
        const i = await io.choose('Какой ключ или адрес?', items, { footer: '● задан  ○ не задан (серый — необязательный)' });
        if (i === undefined) return;
        if (await askSetting(io, env, SECRETS[i])) await showChecks(env, [SECRETS[i].group]);
    }
}

export async function checkAll(env: Env) {
    section('Проверка ключей и адресов');
    await showChecks(env);
}

// ------------------------------------------------------------------ hosts

function rawHost(file: string, name: string): Record<string, unknown> {
    const v = parseDocument(readFleet(file)).getIn(['hosts', name]);
    return (v && typeof v === 'object' && 'toJSON' in v ? (v as { toJSON: () => Record<string, unknown> }).toJSON() : {}) ?? {};
}

async function peersNotInFleet(env: Env): Promise<{ extras: TailscalePeer[]; others: number; error?: string }> {
    try {
        const peers = await tailscalePeers(env.config);
        const hosts = [...env.ctx.inventory().hosts.values()];
        const all = peers.filter((p) => !p.self && !isPersonalDevice(p) && !hosts.some((h) => matchPeer(h, [p])));
        const extras = all.filter((p) => !p.os || /linux/i.test(p.os));
        return { extras, others: all.length - extras.length };
    } catch (e) {
        return { extras: [], others: 0, error: (e as Error).message };
    }
}

async function hostsSummary(io: Io, env: Env, offer: boolean) {
    const inv = env.ctx.inventory();
    const off = [...inv.hosts.values()].filter((h) => h.disabled).length;
    ok(`fleet.yaml: ${inv.hosts.size} хостов${off ? `, ${off} отключено` : ''}, ${inv.groups.size} групп ${c.gray(env.config.inventoryFile)}`);
    const { extras, others, error } = await peersNotInFleet(env);
    if (error) return bad(`tailnet: ${error}`);
    if (!extras.length) return ok(`все Linux-машины tailnet уже в fleet.yaml${others ? c.gray(` (ещё ${others} не-Linux: телефоны, ноутбуки)`) : ''}`);
    console.log(`  ${c.yellow('●')} в tailnet без записи в fleet.yaml: ${extras.map((p) => p.hostName).join(', ')}`);
    if (offer && (await io.confirm('  Добавить их сейчас?'))) await hostFromTailnet(io, env);
}

export async function hostsList(env: Env) {
    const inv = env.ctx.inventory();
    const rows = [...inv.hosts.values()].map((h) => ({
        host: h.name,
        address: h.address,
        user: h.user ?? '',
        roles: h.roles.join(','),
        group: h.groups.join(','),
        tags: h.tags.join(','),
        state: h.disabled ? 'отключён' : '',
    }));
    console.log(rows.length ? table(rows) : c.gray(`В ${env.config.inventoryFile} пока нет хостов.`));
}

async function pickHost(io: Io, env: Env, title: string): Promise<string | undefined> {
    const hosts = [...env.ctx.inventory().hosts.values()];
    if (!hosts.length) {
        console.log(c.gray('В fleet.yaml пока нет хостов.'));
        return undefined;
    }
    const i = await io.choose(
        title,
        hosts.map((h) => ({ label: h.disabled ? c.gray(`${h.name} (отключён)`) : h.name, hint: [h.address, h.roles.join(','), h.groups.join(',')].filter(Boolean).join(' · '), keys: h.address })),
    );
    return i === undefined ? undefined : hosts[i].name;
}

/** Existing values plus «+ новое…»; returns the chosen list or undefined on Esc. */
async function pickList(io: Io, title: string, known: string[], current: string[], about?: Record<string, string>, fixed = false): Promise<string[] | undefined> {
    const all = fixed ? known : [...new Set([...known, ...current])].sort();
    const items: Choice[] = [...all.map((x) => ({ label: x, hint: about?.[x] })), ...(fixed ? [] : [{ label: c.gray('+ новое…') }])];
    const got = await io.chooseMany(title, items, all.map((x, i) => (current.includes(x) ? i : -1)).filter((i) => i >= 0));
    if (got === undefined) return undefined;
    const out = got.filter((i) => i < all.length).map((i) => all[i]);
    if (got.includes(all.length)) {
        const more = (await io.ask(`  ${c.gray('новые, через запятую:')} `)).split(',').map((s) => s.trim()).filter(Boolean);
        out.push(...more);
    }
    return [...new Set(out)];
}

/** remnanode brings edge along, panel brings docker (the inventory adds them): keep fleet.yaml short. */
const lean = (roles: string[]) => roles.filter((r) => !(r === 'edge' && roles.includes('remnanode')) && !(r === 'docker' && roles.includes('panel')));

const known = (env: Env) => {
    const inv = env.ctx.inventory();
    const hosts = [...inv.hosts.values()];
    return { groups: [...inv.groups.keys()], tags: [...new Set(hosts.flatMap((h) => h.tags))], defaultUser: inv.defaultUser };
};

/** Show a fleet.yaml plan, ask, write; offer a commit when fleet.yaml lives in git. */
async function commitPlan(io: Io, env: Env, edits: HostEdit[], what: string): Promise<boolean> {
    let plan;
    try {
        plan = planFleet(env.config.inventoryFile, edits);
    } catch (e) {
        bad((e as Error).message.replace(/\n\s*/g, ' '));
        return false;
    }
    const changed = plan.diff.filter((l) => /^[-+]/.test(l));
    if (!changed.length) {
        ok('fleet.yaml уже такой — менять нечего');
        return false;
    }
    section(`План: ${what}`);
    for (const s of plan.summary) console.log(`  ${s}`);
    console.log(changed.map((l) => `    ${l.startsWith('+') ? c.green(l) : c.red(l)}`).join('\n'));
    note(`файл: ${plan.file}; серверы не трогаются`);
    if (!(await io.confirm('Записать в fleet.yaml?'))) {
        note('Отменено, fleet.yaml не менялся.');
        return false;
    }
    const { backup } = writeFleet(plan, env.config.stateDir);
    env.ctx.inventory();
    env.ctx.state.log({ tool: 'console:fleet.yaml', host: edits.map((e) => e.name).join(','), action: plan.summary.join('; '), ok: true, result: 'written', ms: 0, planHash: plan.hash });
    ok(`записано${backup ? c.gray(` (прежний файл: ${backup})`) : ''}`);
    await offerCommit(io, plan.file, `fleet: ${plan.summary.join('; ').slice(0, 120)}`);
    return true;
}

async function offerCommit(io: Io, file: string, message: string) {
    let root: string;
    try {
        root = execFileSync('git', ['-C', path.dirname(file), 'rev-parse', '--show-toplevel'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
        return;
    }
    if (!(await io.confirm(`  fleet.yaml в git-репозитории ${root}. Закоммитить (без push)?`))) return;
    try {
        execFileSync('git', ['-C', root, 'add', file], { stdio: 'ignore' });
        execFileSync('git', ['-C', root, 'commit', '-m', message, '--', file], { stdio: 'ignore' });
        ok(`коммит в ${root}; отправить: git -C ${root} push`);
    } catch (e) {
        bad(`git commit не вышел: ${(e as Error).message.split('\n')[0]}`);
    }
}

async function sshCheck(env: Env, name: string, address: string, user?: string, port?: number) {
    process.stdout.write(c.gray(`  … ssh ${user ? `${user}@` : ''}${address}\n`));
    const h = { ...adhocHost(name, address, user ?? 'root'), ...(port ? { port } : {}) };
    const r = await env.ctx.transport.exec(h, 'hostname; . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"', { timeoutMs: 20_000 });
    if (r.ok) ok(`ssh работает: ${r.stdout.trim().split('\n').join(' · ')}`);
    else bad(`ssh не вышел: ${r.error ?? r.stderr.trim().split('\n').pop()} — запись всё равно можно сохранить`);
}

export async function hostAdd(io: Io, env: Env, preset: { name?: string; address?: string } = {}) {
    section('Новый хост в fleet.yaml');
    const inv = env.ctx.inventory();
    let name = preset.name ?? '';
    for (;;) {
        name = (await io.ask(`  ${c.bold('имя')} ${c.gray('(ключ в fleet.yaml, например pl3)')}: `, { initial: name })).trim();
        if (!name) return;
        if (!/^[\w.-]+$/.test(name)) bad('только буквы, цифры, . _ -');
        else if (inv.hosts.has(name)) bad(`${name} уже есть — это пункт «Изменить хост»`);
        else if (inv.groups.has(name)) bad(`${name} — имя группы`);
        else break;
    }
    const peers = await tailscalePeers(env.config).catch(() => [] as TailscalePeer[]);
    const guess = preset.address ?? peers.find((p) => [name, `node-${name}`].includes(p.hostName.toLowerCase()))?.dnsName.split('.')[0] ?? '';
    const address = (await io.ask(`  ${c.bold('адрес для ssh')} ${c.gray('(tailnet-имя, IP или алиас из ~/.ssh/config; пусто — как имя)')}: `, { initial: guess })).trim();
    const k = known(env);
    const user = (await io.ask(`  ${c.bold('пользователь ssh')}: `, { initial: k.defaultUser ?? 'root' })).trim();
    const roles = (await pickList(io, 'Роли (что на нём проверять)', [...ROLES], name.startsWith('node') || guess.startsWith('node-') ? ['remnanode'] : ['edge'], ROLE_RU, true)) ?? [];
    const groups = (await pickList(io, 'Группы', k.groups, [])) ?? [];
    const tags = (await pickList(io, 'Теги', k.tags, k.tags.includes('prod') && roles.includes('remnanode') ? ['prod'] : [])) ?? [];
    const set: Record<string, unknown> = { address: address || undefined, user: user && user !== k.defaultUser ? user : undefined, roles: lean(roles), tags };
    if (roles.includes('remnanode')) {
        set.domain = (await io.ask(`  ${c.bold('домен ноды')} ${c.gray('(TLS; Enter — нет)')}: `)).trim() || undefined;
        set.panelNode = (await io.ask(`  ${c.bold('имя ноды в панели')} ${c.gray('(Enter — найти по адресу/домену)')}: `)).trim() || undefined;
    }
    set.provider = (await io.ask(`  ${c.bold('провайдер')} ${c.gray('(Enter — нет)')}: `)).trim() || undefined;
    if (await io.confirm('  Проверить ssh-доступ сейчас?')) await sshCheck(env, name, address || name, user, undefined);
    await commitPlan(io, env, [{ op: 'add', name, set: set as HostEdit['set'], groups }], `добавить ${name}`);
}

export async function hostFromTailnet(io: Io, env: Env) {
    const { extras, others, error } = await peersNotInFleet(env);
    if (error) return bad(`tailnet: ${error}`);
    if (!extras.length) return ok(`все Linux-машины tailnet уже в fleet.yaml${others ? c.gray(` (ещё ${others} не-Linux)`) : ''}`);
    const days = (p: TailscalePeer) => (p.lastSeen ? Math.floor((Date.now() - Date.parse(p.lastSeen)) / 86_400_000) : undefined);
    const got = await io.chooseMany(
        'Какие устройства tailnet добавить в fleet.yaml?',
        extras.map((p) => ({ label: p.hostName, hint: [p.dnsName.split('.')[0], p.os, p.online ? 'в сети' : `не в сети ${days(p) ?? '?'} дн`].filter(Boolean).join(' · ') })),
        [],
    );
    if (!got?.length) return;
    const k = known(env);
    const edits: HostEdit[] = [];
    const taken = new Set(env.ctx.inventory().hosts.keys());
    for (const i of got) {
        const p = extras[i];
        section(p.hostName);
        let name = p.hostName.toLowerCase().replace(/^node-/, '').replace(/[^\w.-]+/g, '-');
        for (;;) {
            name = (await io.ask(`  ${c.bold('имя в fleet.yaml')}: `, { initial: name })).trim();
            if (!name) break;
            if (!/^[\w.-]+$/.test(name)) bad('только буквы, цифры, . _ -');
            else if (taken.has(name) || k.groups.includes(name)) bad(`${name} уже занято`);
            else break;
        }
        if (!name) continue;
        taken.add(name);
        const roles = (await pickList(io, `Роли ${name}`, [...ROLES], p.hostName.startsWith('node-') ? ['remnanode'] : ['edge'], ROLE_RU, true)) ?? [];
        const groups = (await pickList(io, `Группы ${name}`, k.groups, [])) ?? [];
        edits.push({ op: 'add', name, set: { address: p.dnsName.split('.')[0] || p.hostName, roles: lean(roles), ...(p.online ? {} : { notes: `не в сети с ${p.lastSeen?.slice(0, 10) ?? '?'}` }) }, groups });
    }
    if (edits.length) await commitPlan(io, env, edits, `добавить ${edits.map((e) => e.name).join(', ')}`);
}

const FIELD_RU: Record<string, string> = {
    address: 'адрес ssh',
    user: 'пользователь',
    port: 'порт ssh',
    roles: 'роли',
    groups: 'группы',
    tags: 'теги',
    domain: 'домен ноды',
    panelNode: 'нода в панели',
    provider: 'провайдер',
    notes: 'заметка',
};

export async function hostEdit(io: Io, env: Env) {
    const name = await pickHost(io, env, 'Какой хост изменить?');
    if (!name) return;
    const raw = rawHost(env.config.inventoryFile, name);
    const k = known(env);
    const cur: Record<string, unknown> = { ...raw, groups: env.ctx.inventory().get(name).groups };
    const next: Record<string, unknown> = { ...cur };
    const fields = Object.keys(FIELD_RU);
    const fmt = (v: unknown) => (v === undefined || v === '' || (Array.isArray(v) && !v.length) ? c.gray('—') : Array.isArray(v) ? v.join(', ') : String(v));
    const diff = () => fields.filter((f) => JSON.stringify(cur[f] ?? null) !== JSON.stringify(next[f] ?? null));
    let last = 0;
    for (;;) {
        const changed = diff();
        const items: Choice[] = [
            ...(changed.length ? [{ label: c.green(`✔ Сохранить (${changed.map((f) => FIELD_RU[f]).join(', ')})`) }] : []),
            ...fields.map((f) => ({ label: `${FIELD_RU[f].padEnd(14)} ${changed.includes(f) ? c.yellow(fmt(next[f])) : fmt(next[f])}`, keys: f })),
        ];
        const i = await io.choose(`Хост ${name}`, items, { initial: last, footer: 'Enter — изменить поле · Esc — выйти' });
        if (i === undefined) {
            if (!changed.length || (await io.confirm('Выйти без сохранения?'))) return;
            continue;
        }
        const off = changed.length ? 1 : 0;
        if (off && i === 0) break;
        const f = fields[i - off];
        if (f === 'roles') next.roles = lean((await pickList(io, 'Роли', [...ROLES], (next.roles as string[]) ?? [], ROLE_RU, true)) ?? (next.roles as string[]) ?? []);
        else if (f === 'groups') next.groups = (await pickList(io, 'Группы', k.groups, (next.groups as string[]) ?? [])) ?? next.groups;
        else if (f === 'tags') next.tags = (await pickList(io, 'Теги', k.tags, (next.tags as string[]) ?? [])) ?? next.tags;
        else {
            const v = (await io.ask(`  ${c.bold(FIELD_RU[f])} ${c.gray('(пусто — убрать)')}: `, { initial: next[f] === undefined ? '' : String(next[f]) })).trim();
            next[f] = v === '' ? undefined : f === 'port' ? Number(v) : v;
        }
        // something changed: the cursor waits on «Сохранить»
        last = diff().length ? 0 : fields.indexOf(f);
    }
    const changed = diff();
    const set: Record<string, unknown> = {};
    const unset: HostField[] = [];
    for (const f of changed.filter((f) => f !== 'groups')) {
        const v = next[f];
        if (v === undefined || (Array.isArray(v) && !v.length)) unset.push(f as HostField);
        else set[f] = v;
    }
    await commitPlan(io, env, [{ op: 'update', name, set: set as HostEdit['set'], unset, ...(changed.includes('groups') ? { groups: next.groups as string[] } : {}) }], `изменить ${name}`);
}

export async function hostToggle(io: Io, env: Env) {
    const name = await pickHost(io, env, 'Какой хост отключить или включить?');
    if (!name) return;
    const off = env.ctx.inventory().get(name).disabled;
    note(off ? `${name} сейчас отключён: снова войдёт в «all», роли и теги.` : `${name} выпадет из «all», ролей и тегов (по имени по-прежнему доступен). Сервер не трогается.`);
    await commitPlan(io, env, [{ op: off ? 'enable' : 'disable', name }], `${off ? 'включить' : 'отключить'} ${name}`);
}

export async function hostRemove(io: Io, env: Env) {
    const name = await pickHost(io, env, 'Какой хост удалить из fleet.yaml?');
    if (!name) return;
    note('Удаляется только запись (и членство в группах). Сервер, панель и tailnet не трогаются.');
    note('Временно убрать хост из «all» — «Отключить».');
    await commitPlan(io, env, [{ op: 'remove', name }], `удалить ${name}`);
}

/** Where fleet.yaml is and whether it exists: shown at the top of the hosts part. */
export function fleetFileLine(config: Config): string {
    return fs.existsSync(config.inventoryFile) ? config.inventoryFile : `${config.inventoryFile} (ещё нет — появится с первым хостом)`;
}
