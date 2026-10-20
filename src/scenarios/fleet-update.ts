import { z } from 'zod';
import { ScenarioDef, StepDef } from '../core/scenario.js';
import { list, listParam } from './common.js';

/**
 * fleet_update: security updates across the fleet —
 * one host per step (a canary first), each host checked back (ssh over the tailnet, panel node connected)
 * before the next, never hosts in the `hands-off` group/tag, never a reboot: hosts that want one are listed at the end.
 * Lessons: upgrading tailscale restarts it and cuts mia's ssh — the step then looks failed although apt
 * finished (dpkg --audit + history.log tell); docker upgrades restart every container (clients reconnect).
 */

/** Target expression with the hosts that are never updated by a run. */
export function updateTarget(target: string, exclude: string[]): string {
    const never = ['hands-off', ...exclude];
    return [target, ...never.filter((x) => x && !target.split(',').includes(`!${x}`)).map((x) => `!${x}`)].join(',');
}

/** Hosts of an apt_upgrade dry run that have something to install, canary first, then by name. */
export function updateQueue(plan: Array<{ host: string; now?: { upgradable?: number; security?: number } }>, securityOnly: boolean, canary?: string): string[] {
    const hosts = plan.filter((r) => (securityOnly ? (r.now?.security ?? 0) : (r.now?.upgradable ?? 0)) > 0).map((r) => r.host);
    const sorted = [...new Set(hosts)].sort();
    return canary && sorted.includes(canary) ? [canary, ...sorted.filter((h) => h !== canary)] : sorted;
}

export const fleetUpdate: ScenarioDef = {
    name: 'fleet_update',
    title: 'Обновления флота: по одному хосту, канарейка первой, без перезагрузок',
    description:
        'Security-обновления (или все) по флоту: пробный прогон показывает, где что ставится, затем хосты по одному — канарейка первой; после каждого проверка, что хост вернулся по тайлнету и его нода в панели подключена. Хосты группы/тега hands-off — никогда. Ядра и драйверы — только если попросить, docker — отдельно. Перезагрузок нет: в конце список хостов, которые её ждут.',
    params: {
        target: z.string().default('all').describe('какие хосты (all, группа, role:remnanode …); hands-off исключается всегда'),
        exclude: listParam('ещё исключить, через запятую'),
        securityOnly: z.boolean().default(true).describe('только пакеты из *-security'),
        includeKernel: z.boolean().default(false).describe('ядра и драйверы видеокарт (подействуют только после перезагрузки)'),
        skipDocker: z.boolean().default(true).describe('не трогать docker/containerd: их обновление перезапускает все контейнеры (remnanode — клиенты переподключатся)'),
        canary: z.string().optional().describe('хост-канарейка, обновляется первым (по умолчанию — первый по имени)'),
    },
    steps: (p, v) => {
        const target = updateTarget(p.target, list(p.exclude));
        const apt = (host: string) => ({ target: host, securityOnly: p.securityOnly, includeKernel: p.includeKernel, skipDocker: p.skipDocker });
        const queue: string[] = v.queue ?? [];
        const steps: StepDef[] = [
            {
                id: 'plan',
                title: `Что ставится: пробный прогон apt_upgrade на ${target}`,
                kind: 'check',
                tool: 'apt_upgrade',
                args: () => ({ ...apt(target), apply: false }),
                save: (d, r) => {
                    r.vars.queue = updateQueue(d?.plan ?? [], p.securityOnly, p.canary);
                    r.vars.blocked = d?.blocked ?? [];
                },
                expect: (d) => (Array.isArray(d?.plan) ? true : 'пробный прогон не вернул план'),
            },
            {
                id: 'panel-nodes',
                title: 'Ноды панели у хостов очереди (для проверки после обновления)',
                kind: 'check',
                run: async (ctx, r) => {
                    const inv = ctx.inventory();
                    return Object.fromEntries((r.vars.queue as string[]).map((h) => [h, inv.get(h).panelNode ?? null]));
                },
                save: (d, r) => (r.vars.panelNodes = d),
            },
        ];
        for (const host of queue) {
            steps.push(
                {
                    id: `upgrade-${host}`,
                    title: `${host}: обновить${host === queue[0] ? ' (канарейка)' : ''} — при обновлении tailscale ssh рвётся, это не сбой apt`,
                    kind: 'mia',
                    tool: 'apt_upgrade',
                    args: () => apt(host),
                },
                {
                    id: `back-${host}`,
                    title: `${host}: вернулся по тайлнету, пакеты в порядке`,
                    kind: 'check',
                    run: async (ctx) => {
                        const res = await ctx.transport.exec(ctx.inventory().get(host), 'dpkg --audit | head -n 5; echo "audit-rc=$?"; [ -f /var/run/reboot-required ] && echo REBOOT_REQUIRED || true; systemctl is-system-running 2>/dev/null || true', { timeoutMs: 30_000 });
                        return res.ok ? res.stdout.trim() : `нет ssh: ${res.error}`;
                    },
                    poll: { timeoutSec: 300, everySec: 20 },
                    expect: (d) => {
                        const s = String(d);
                        if (s.startsWith('нет ssh')) return `${host} пока недоступен: ${s}`;
                        if (/^\s*The following packages|not fully installed|half-configured/m.test(s)) return `dpkg --audit на ${host} нашёл недоустановленные пакеты:\n${s}`;
                        return true;
                    },
                    save: (d, r) => {
                        if (String(d).includes('REBOOT_REQUIRED')) r.vars.reboot = [...new Set([...(r.vars.reboot ?? []), host])];
                    },
                },
                {
                    id: `panel-${host}`,
                    title: `${host}: нода в панели подключена`,
                    kind: 'check',
                    panel: true,
                    tool: 'nodes_list',
                    when: (r) => !!r.vars.panelNodes?.[host],
                    args: (r) => ({ filter: r.vars.panelNodes[host] }),
                    poll: { timeoutSec: 300, everySec: 15 },
                    expect: (d, r) => {
                        const n = ((d?.nodes ?? []) as Array<{ name: string; state: string }>).find((x) => x.name === r.vars.panelNodes[host]);
                        return n?.state === 'connected' ? true : `панель: ${r.vars.panelNodes[host]} — ${n?.state ?? 'не найдена'}`;
                    },
                },
            );
        }
        steps.push({
            id: 'reboot',
            title: 'Перезагрузки — только руками',
            kind: 'manual',
            when: (r) => (r.vars.reboot ?? []).length > 0,
            instruction: (r) =>
                `Перезагрузку ждут: ${(r.vars.reboot as string[]).join(', ')}. Автоперезагрузок нет: когда удобно — mia reboot <хост> по одному.`,
        });
        steps.push({ id: 'snapshot', title: 'Снимок после обновления', kind: 'check', tool: 'fleet_snapshot', when: (r) => (r.vars.queue ?? []).length > 0, args: (r) => ({ target: (r.vars.queue as string[]).join(','), reason: 'fleet_update' }) });
        return steps;
    },
};
