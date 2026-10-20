import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { stringify } from 'yaml';
import { c, hlYaml } from './color.js';
import { TITLES, startConsole } from './console.js';
import { writeDigest } from './core/digest.js';
import { Advance, Decision, ScenarioEngine } from './core/scenario.js';
import { loadSecrets } from './core/secrets.js';
import { Config, loadConfig } from './config.js';
import { Ctx } from './core/ctx.js';
import { startWeb } from './web/server.js';
import { DemoTransport, demoEnv } from './demo.js';
import { Transport } from './core/ssh.js';
import { SCENARIOS } from './scenarios/index.js';
import { secretsCmd } from './secrets-cli.js';
import { createServer, VERSION } from './server.js';
import { registry } from './tools/helpers.js';
import { spin } from './tui.js';
import { callTool, firstSentence, parseArgs, showResult, table, walk, yamlOut } from './ui.js';

export { firstSentence };

const HELP = `${c.bold(`mia ${VERSION}`)} — управление флотом: MCP-сервер и консоль

  ${c.cyan('mia')}                          консоль: меню стрелками (буквы — поиск по всему), карточка
                               параметров, план → «Выполнить?» (Enter — да)
  ${c.cyan('mia web')} [--port N]            то же в браузере: таблица серверов, кнопки, план → «Выполнить»
  ${c.cyan('mia web --behind-proxy --host имя')} [--port N]  службой за Traefik на этой же машине (без ключа)
  ${c.cyan('mia web --demo')}, ${c.cyan('mia --demo')}   потренироваться на выдуманном флоте: жать можно всё, серверы не трогаются
  ${c.cyan('mia setup')}                    настройка по порядку: ключи и адреса сервисов, потом хосты
  ${c.cyan('mia update')} [цель]            обновить пакеты (по умолчанию на всех): план → Enter
  ${c.cyan('mia node-update')} [цель]       обновить remnanode на всех нодах: план → Enter
  ${c.cyan('mia reboot')} [цель]            перезагрузить: выбор серверов → план → ввести число/имя
  ${c.cyan('mia logs')} [хост [сервис]]     логи: выбор сервера и сервиса из списка
  ${c.cyan('mia')} <слова>                  поиск по всем действиям: mia логи, mia днс, mia ребут
  ${c.cyan('mia status')} [цель]            статус всего флота (инвентарь + весь tailnet)
  ${c.cyan('mia audit')} [цель]             аудит по стандарту флота
  ${c.cyan('mia hosts')}                    инвентарь (fleet.yaml)
  ${c.cyan('mia discover')}                 сверка: tailnet и панель против fleet.yaml
  ${c.cyan('mia snapshot')} [цель]          снять снимок состояния (в cron — для истории изменений)
  ${c.cyan('mia changes')} [цель]           что поменялось с прошлого снимка
  ${c.cyan('mia tools')}                    все инструменты (✎ — меняют серверы)
  ${c.cyan('mia call')} <инструмент> [ключ=значение …]
                               любой инструмент: сначала холостой прогон, потом
                               тот же вызов с apply=true planHash=…
  ${c.cyan('mia scenario')}                 ранбуки: правила xray, обновления флота
  ${c.cyan('mia scenario')} <имя> ключ=значение …   запустить; ${c.cyan('resume')} <прогон> — продолжить;
                               ${c.cyan('show')} <прогон> — журнал; ${c.cyan('step')} <прогон> apply|done|skip|retry;
                               ${c.cyan('set')} <прогон> ключ=значение — поменять параметр прогона
  ${c.cyan('mia secrets')} [set ИМЯ | unset ИМЯ | check]
                               ключи и адреса (панель, Tailscale, Cloudflare, Gitea, Beszel, MIA_REPOS …):
                               ~/.config/mia/secrets.env (600) или ссылки op://; значения не показываются
  ${c.cyan('mia sessions-digest')} [--dir ~/.claude/projects] [--out ~/mia-inventory]
                               дайджест прошлых сессий Claude Code (локально, секреты маскируются)
  ${c.cyan('mia mcp')}                      MCP-сервер на stdio (для Claude Code / Desktop)

Цели: all | имя | nl-* | группа | role:remnanode | tag:prod; через запятую, !x — исключить.
Добавьте --json, чтобы получить сырой JSON вместо таблиц.
Окружение: MIA_INVENTORY (fleet.yaml), MIA_STATE_DIR, MIA_READONLY, MIA_NUMBERS=1 (меню без стрелок), MIA_REPOS
(ops=~/ops-scripts,haproxy=~/haproxy-configs), MIA_REMNAWAVE_MCP (запуск mcp-remnawave), ключи — mia secrets.`;

async function main() {
    const argv = process.argv.slice(2);
    const json = argv.includes('--json');
    // a made-up fleet: nothing is read from the owner's files, nothing leaves this machine
    const demo = argv.includes('--demo');
    const [cmd, ...rest] = argv.filter((a) => a !== '--json' && a !== '--demo');
    if (cmd === 'help' || cmd === '--help' || cmd === '-h' || (!cmd && !process.stdin.isTTY && !demo)) {
        console.log(HELP);
        return;
    }
    if (cmd === '--version' || cmd === 'version') {
        console.log(VERSION);
        return;
    }

    if (cmd === 'sessions-digest') {
        // только локально: читает переписки Claude Code, пишет замаскированный дайджест; серверов не касается
        const opt = (k: string, d: string) => {
            const i = rest.indexOf(k);
            return i >= 0 && rest[i + 1] ? rest[i + 1] : d;
        };
        const home = os.homedir();
        const res = writeDigest(opt('--dir', path.join(home, '.claude', 'projects')), opt('--out', path.join(home, 'mia-inventory')));
        console.log(yamlOut(res));
        console.log(`\nОткройте ${res.outDir}/index.md и entities.md. Секреты замаскированы, но перед тем как делиться — просмотрите.`);
        return;
    }

    if (cmd === 'secrets') {
        await secretsCmd(rest, { config: () => (loadSecrets(), loadConfig()), ctx: () => createServer(loadConfig()).ctx, table });
        return;
    }

    let config: Config;
    let transport: Transport | undefined;
    if (demo) {
        const env = demoEnv();
        process.env.MIA_SECRETS_FILE = env.MIA_SECRETS_FILE;
        config = { ...loadConfig(env), demo: true };
        transport = new DemoTransport(config);
    } else {
        // secrets.env (и ссылки op://) → окружение, до того как его кто-то прочтёт
        const sec = loadSecrets();
        if (sec.warning) console.error(c.red(`mia: ${sec.warning}`));
        config = loadConfig();
    }
    const { server, ctx, engine, bridge } = createServer(config, transport);

    if (cmd === 'mcp' && demo) throw new Error('--demo только для консоли и web');
    if (cmd === 'mcp') {
        await server.connect(new StdioServerTransport());
        return;
    }

    try {
        if (!cmd) return await startConsole({ ctx, engine, config });
        if (cmd === 'setup') return await startConsole({ ctx, engine, config }, { setup: 'wizard' });
        if (cmd === 'web') return await webCmd({ ctx, config }, rest);
        // the frequent actions as commands: straight to the plan, one Enter to run
        const quick: Record<string, { tool: string; preset?: Record<string, unknown>; ask?: string[] }> = {
            update: { tool: 'apt_upgrade', preset: { target: 'all' } },
            'node-update': { tool: 'remnanode_update', preset: { target: 'role:remnanode' } },
            reboot: { tool: 'host_reboot', ask: ['target'] },
            logs: { tool: 'host_logs' },
        };
        if (quick[cmd] && process.stdin.isTTY) {
            const q = quick[cmd];
            if (!registry.has(q.tool)) throw new Error(`mia ${cmd} меняет серверы, а сейчас режим только чтения (MIA_READONLY=true) — запустите без него`);
            const positional = rest.filter((a) => !a.includes('='));
            const preset: Record<string, unknown> = { ...(q.preset ?? {}), ...parseArgs(rest.filter((a) => a.includes('=')), registry.get(q.tool)?.schema ?? {}) };
            if (positional[0]) preset[q.tool === 'host_logs' ? 'host' : 'target'] = positional[0];
            if (positional[1] && q.tool === 'host_logs') preset.source = positional[1];
            return await startConsole({ ctx, engine, config }, { tool: q.tool, preset, ask: preset.target ? [] : q.ask }, true);
        }
        if (cmd === 'scenario') return await scenarioCmd(engine, rest);
        if (cmd === 'tools') {
            for (const [name, t] of [...registry].sort()) console.log(`${t.readonly ? ' ' : c.yellow('✎')} ${c.cyan(name.padEnd(26))} ${TITLES[name] ?? firstSentence(t.description, 110)}`);
            console.log(c.gray('\n✎ — меняет серверы: сначала план, потом apply. Запуск: mia call <инструмент> ключ=значение … или просто mia'));
            return;
        }
        const shortcuts: Record<string, string> = { status: 'fleet_status', audit: 'fleet_audit', hosts: 'fleet_hosts', snapshot: 'fleet_snapshot', changes: 'fleet_changes', discover: 'fleet_discover' };
        let tool: string;
        let args: Record<string, unknown>;
        const shapeOf = (t: string) => registry.get(t)?.schema ?? {};
        if (cmd === 'call') {
            if (!rest.length) throw new Error('как: mia call <инструмент> [ключ=значение …]');
            tool = rest[0];
            args = parseArgs(rest.slice(1), shapeOf(tool));
        } else if (shortcuts[cmd]) {
            tool = shortcuts[cmd];
            const positional = rest.filter((a) => !a.includes('='));
            args = parseArgs(rest.filter((a) => a.includes('=')), shapeOf(tool));
            if (positional[0] && tool !== 'fleet_discover') args.target = positional[0];
        } else if (process.stdin.isTTY && !cmd.startsWith('-')) {
            // mia логи / mia ребут / mia днс: the words go to the search over every action
            return await startConsole({ ctx, engine, config }, { search: [cmd, ...rest].join(' ') }, true);
        } else {
            console.error(HELP);
            process.exit(2);
        }
        // on a terminal the hosts show up as they answer; --json and pipes get the result only
        const res = json || !process.stdout.isTTY ? await callTool(tool, args) : await spin(TITLES[tool] ?? tool, () => callTool(tool, args));
        if (res.isError) {
            console.error(c.red(res.text));
            process.exit(1);
        }
        console.log(json ? res.text : showResult(tool, res.data));
    } finally {
        await bridge?.close();
    }
}

async function scenarioCmd(engine: ScenarioEngine, rest: string[]) {
    const [sub, ...more] = rest;
    if (!sub || sub === 'list') {
        for (const s of engine.list()) {
            console.log(`${c.bold(c.cyan(s.name.padEnd(16)))} ${s.title}`);
            for (const p of s.params) console.log(`    ${p.required ? c.red('*') : ' '} ${p.name.padEnd(17)} ${c.gray([p.about, 'default' in p ? `(по умолчанию ${JSON.stringify(p.default)})` : ''].filter(Boolean).join(' '))}`);
        }
        const runs = engine.runs().slice(0, 10);
        if (runs.length) console.log(`\n${c.bold('Прогоны:')}\n${table(runs)}`);
        console.log(`\n${c.red('*')} — обязательно. Запуск: mia scenario <имя> ключ=значение …  (или просто mia → «Перенос и ранбуки»)`);
        return;
    }
    if (sub === 'runs') return console.log(table(engine.runs()));
    if (sub === 'show') {
        const r = engine.load(need(more[0], 'id прогона'));
        return console.log(hlYaml(stringify({ run: r.id, scenario: r.scenario, params: r.params, vars: r.vars, finished: !!r.finished, log: r.log }, { lineWidth: 0 })));
    }
    if (sub === 'set') {
        const id = need(more[0], 'id прогона');
        const scn = engine.load(id).scenario;
        return await walk(engine, await engine.setParams(id, parseArgs(more.slice(1), SCENARIOS.get(scn)!.params)));
    }
    if (sub === 'step') {
        const decision = need(more[1], 'решение (apply|done|skip|retry)') as Decision;
        return console.log(JSON.stringify(await engine.decide(need(more[0], 'id прогона'), decision), null, 1));
    }
    let adv: Advance;
    if (sub === 'resume') adv = await engine.resume(need(more[0], 'id прогона'));
    else {
        const def = SCENARIOS.get(sub);
        if (!def) throw new Error(`нет ранбука ${sub}; список: mia scenario`);
        adv = await engine.start(sub, parseArgs(more, def.params));
    }
    await walk(engine, adv);
}

/** mia web [--port N] [--no-open]: the page on this machine; runs until Ctrl+C. */
async function webCmd(deps: { ctx: Ctx; config: Config }, rest: string[]) {
    const i = rest.indexOf('--port');
    const want = i >= 0 ? Number(rest[i + 1]) : 7331;
    // --behind-proxy --host NAME [--host NAME2]: as a service behind Traefik on this machine (see web/server.ts)
    const proxyHosts = rest.includes('--behind-proxy') ? rest.flatMap((a, k) => (a === '--host' && rest[k + 1] ? [rest[k + 1].toLowerCase()] : [])) : [];
    if (rest.includes('--behind-proxy') && !proxyHosts.length) throw new Error('--behind-proxy: укажите --host имя (например dash.example.com)');
    const web = proxyHosts.length ? await startWeb(deps, { port: want, proxyHosts }) : await startWeb(deps, { port: want }).catch(() => startWeb(deps, { port: 0 }));
    if (proxyHosts.length) console.log(`${c.bold('mia web')} — 127.0.0.1:${new URL(web.url).port} за прокси для ${proxyHosts.join(', ')} (без ключа: доступ решает прокси)`);
    else {
        console.log(`${c.bold('mia web')} — ${c.cyan(web.url)}`);
        console.log(c.gray('В ссылке ключ этого запуска; страница работает только на этом компьютере (127.0.0.1). Ctrl+C — остановить.'));
    }
    if (!proxyHosts.length && !rest.includes('--no-open')) {
        const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'explorer' : 'xdg-open';
        spawn(opener, [web.url], { stdio: 'ignore', detached: true }).on('error', () => undefined).unref();
    }
    await new Promise<void>((resolve) => {
        process.once('SIGINT', () => resolve());
        process.once('SIGTERM', () => resolve()); // systemd stop
    });
    await web.close();
}

function need(v: string | undefined, what: string): string {
    if (!v) throw new Error(`не хватает: ${what}`);
    return v;
}

main().catch((e) => {
    console.error(c.red(e instanceof Error ? e.message : String(e)));
    process.exit(1);
});
