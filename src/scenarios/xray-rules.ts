import fs from 'node:fs';
import { z } from 'zod';
import { ScenarioDef, StepDef } from '../core/scenario.js';
import { list, listParam, rowsOf } from './common.js';

/**
 * Change xray routing in config profiles. The panel is the source of truth, so edits go to the panel through
 * mcp-remnawave config_profile_patch — one profile at a time, each a dry run with a diff, and after
 * each write the profile's nodes must come back (the panel restarts them) before the next one.
 */
export function ruleOps(p: Record<string, any>): unknown[] {
    const ops: unknown[] = [];
    const at = p.rule ? `/routing/rules[${p.rule}]` : undefined;
    const need = (what: string) => {
        if (!at) throw new Error(`для ${what} нужно rule (селектор вида outboundTag=RU-GOS или ruleTag=ads)`);
        return at;
    };
    if (list(p.addDomains).length) ops.push({ op: 'array_add', path: `${need('addDomains')}/domain`, values: list(p.addDomains) });
    if (list(p.removeDomains).length) ops.push({ op: 'array_remove', path: `${need('removeDomains')}/domain`, values: list(p.removeDomains) });
    if (list(p.addIps).length) ops.push({ op: 'array_add', path: `${need('addIps')}/ip`, values: list(p.addIps) });
    if (list(p.removeIps).length) ops.push({ op: 'array_remove', path: `${need('removeIps')}/ip`, values: list(p.removeIps) });
    if (p.outbound) ops.push({ op: 'replace', path: `${need('outbound')}/outboundTag`, value: p.outbound });
    if (p.newRule) {
        const value = typeof p.newRule === 'string' ? JSON.parse(p.newRule) : p.newRule;
        // lessons from the fleet: conditions inside one rule are AND; an empty inboundTag matches everything
        if (value.domain?.length && value.ip?.length) throw new Error('в newRule и domain, и ip: внутри одного правила это «И» — сделайте два правила');
        if (Array.isArray(value.inboundTag) && value.inboundTag.length === 0) throw new Error('в newRule пустой inboundTag: xray считает это «весь трафик»');
        if (!value.outboundTag && !value.balancerTag) throw new Error('в newRule нужен outboundTag или balancerTag');
        ops.push(at ? { op: 'insert', path: at, position: p.position === 'after' ? 'after' : 'before', value } : { op: 'add', path: '/routing/rules/-', value });
    }
    if (p.ops) ops.push(...(typeof p.ops === 'string' ? JSON.parse(p.ops) : p.ops));
    if (p.opsFile) ops.push(...JSON.parse(fs.readFileSync(p.opsFile, 'utf8')));
    if (!ops.length) throw new Error('менять нечего: укажите addDomains/removeDomains/addIps/removeIps/outbound/newRule, ops или opsFile');
    return ops;
}

export const xrayRules: ScenarioDef = {
    name: 'xray_rules',
    title: 'Правила маршрутизации xray в профилях',
    description:
        'Правка маршрутизации в профилях через mcp-remnawave (источник правды — панель): добавить или убрать домены и IP в правиле, сменить выход, вставить правило или любые операции. По одному профилю в заданном порядке (сначала маленькие, потом большие): dry run с диффом → apply (mcp-remnawave делает бэкап; панель перезапускает xray на всех нодах профиля) → все ноды должны подняться до следующего профиля. Защита: домен+IP в одном новом правиле (это «И») и пустой inboundTag (ловит всё) отклоняются.',
    params: {
        profiles: listParam('какие профили, по порядку (первый — канарейка), или all'),
        rule: z.string().optional().describe('какое правило: селектор внутри /routing/rules[…], например outboundTag=RU-GOS, ruleTag=ads, domain~=geosite:google-gemini'),
        addDomains: listParam('домены / geosite: — добавить в правило'),
        removeDomains: listParam('домены — убрать из правила'),
        addIps: listParam('IP / CIDR / geoip: — добавить'),
        removeIps: listParam('IP — убрать'),
        outbound: z.string().optional().describe('новый outboundTag правила'),
        newRule: z.union([z.string(), z.record(z.unknown())]).optional().describe('целое правило (JSON): вставить перед/после rule или в конец'),
        position: z.enum(['before', 'after']).default('before'),
        ops: z.union([z.string(), z.array(z.record(z.unknown()))]).optional().describe('операции config_profile_patch как есть (JSON)'),
        opsFile: z.string().optional().describe('файл с JSON-массивом операций'),
    },
    steps: (p, v) => {
        ruleOps(p); // fail on start, not halfway
        const steps: StepDef[] = [
            {
                id: 'profiles',
                title: 'Профили и их ноды',
                kind: 'check',
                panel: true,
                tool: 'config_profiles_list',
                args: () => ({}),
                expect: (d: Array<{ name: string; nodes: string[] }>) => {
                    const names = (Array.isArray(d) ? d : []).map((x) => x.name);
                    const want = list(p.profiles);
                    if (!want.length) return `укажите profiles: ${names.join(', ')}`;
                    const missing = want.filter((w) => w !== 'all' && !names.includes(w));
                    return missing.length ? `нет профиля: ${missing.join(', ')} (есть: ${names.join(', ')})` : true;
                },
                save: (d: Array<{ name: string; nodes: string[] }>, r) => {
                    const want = list(p.profiles);
                    r.vars.profiles = want.includes('all') ? d.filter((x) => x.nodes.length).map((x) => x.name) : want;
                    r.vars.nodesOf = Object.fromEntries(d.map((x) => [x.name, x.nodes]));
                },
            },
        ];
        for (const prof of (v.profiles ?? []) as string[]) {
            steps.push(
                {
                    id: `patch:${prof}`,
                    title: `Профиль ${prof}`,
                    kind: 'panel',
                    tool: 'config_profile_patch',
                    args: () => ({ profile: prof, ops: ruleOps(p) }),
                },
                {
                    id: `nodes:${prof}`,
                    title: `Ноды ${prof} перезапустили xray и подключены`,
                    kind: 'check',
                    panel: true,
                    tool: 'nodes_list',
                    args: () => ({}),
                    poll: { timeoutSec: 240, everySec: 15 },
                    expect: (d) => {
                        const rows = rowsOf(d).filter((n) => n.profile === prof && n.state !== 'disabled') as Array<ReturnType<typeof rowsOf>[number] & { xrayUptimeMin?: number }>;
                        const bad = rows.filter((n) => n.state !== 'connected' || n.xrayUptimeMin === undefined);
                        return bad.length
                            ? `не поднялись: ${bad.map((n) => `${n.name} (${n.state}${n.xrayUptimeMin === undefined ? ', xray лежит' : ''})`).join(', ')} — если xray не стартует, верните профиль из бэкапа mcp-remnawave (config_profiles_update)`
                            : true;
                    },
                },
            );
        }
        return steps;
    },
};
