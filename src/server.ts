import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Config } from './config.js';
import { Ctx } from './core/ctx.js';
import { Transport } from './core/ssh.js';
import { registerAllPrompts } from './prompts/index.js';
import { registerActionTools } from './tools/actions.js';
import { registerChangeTools } from './tools/changes.js';
import { registerCopyTools } from './tools/copy.js';
import { registerFleetTools } from './tools/fleet.js';
import { instrument } from './tools/helpers.js';
import { registerHostTools } from './tools/host.js';
import { registerRuProbeTools } from './tools/ruprobe.js';
import { registerScheduleTools } from './tools/schedule.js';
import { registerJobTools } from './tools/jobs.js';
import { registerMediaTools } from './tools/media.js';
import { registerRepoTools } from './tools/repo.js';
import { registerScenarioTools } from './tools/scenarios.js';
import { registerTailnetTools } from './tools/tailnet.js';
import { registerDnsTools } from './tools/dns.js';
import { registerGiteaTools } from './tools/gitea.js';
import { registerBeszelTools } from './tools/beszel.js';
import { registerFileEditTools } from './tools/fileedit.js';
import { registerInventoryTools } from './tools/inventory.js';
import { RemnawaveBridge } from './core/remnawave.js';
import { ScenarioEngine } from './core/scenario.js';
import { SCENARIOS } from './scenarios/index.js';

export const VERSION = '0.1.0';

export function createServer(config: Config, transport?: Transport): { server: McpServer; ctx: Ctx; engine: ScenarioEngine; bridge?: RemnawaveBridge } {
    const server = new McpServer(
        { name: 'mia-assist', version: VERSION },
        {
            instructions: [
                'Fleet of servers (Remnawave nodes, panel, other hosts) reached over ssh / Tailscale. Host names come from the inventory (fleet_hosts).',
                'Start with fleet_status (one row per host) or fleet_audit (findings with codes); host_inspect / host_logs / host_ports / host_firewall for one host.',
                'Targets: all | host | glob | group | role:remnanode | tag:x, comma-separated, !x excludes.',
                'Every tool that changes a host is two-step: call without apply → exact plan per host + planHash; repeat with apply:true and planHash. Disruptive actions (restarts, reboots, upgrades, firewall) roll one host at a time and verify it came back; cheap ones (host_exec, disk_cleanup, cert_renew, geo/blacklist/updates policy) default to 10 at a time — pass batch:1 to go slower. Everything run is journaled (journal_list).',
                'fleet_snapshot + fleet_changes keep a history of what changed on each host, including changes made by hand.',
                'The panel itself (users, hosts, profiles, inbounds) is managed by the remnawave MCP server; here the panel is read only to match hosts to nodes.',
                'Whole operations (xray rule changes across profiles, rolling OS updates) are runbooks: scenario_list → scenario_start → scenario_step. Each changing step is shown as a dry run first; answer apply only after the owner said yes to that step.',
                'Home services: host_services_discover lists what runs on a host; Jellyfin and Tdarr have their own tools (jellyfin_*, tdarr_*) when the host has apps.jellyfin / apps.tdarr. Folders can be given as host paths: they are mapped into the app container.',
            ].join('\n'),
        },
    );
    const ctx = new Ctx(config, transport);
    instrument(server, ctx.out);
    registerFleetTools(server, ctx);
    registerHostTools(server, ctx);
    registerRuProbeTools(server, ctx);
    registerScheduleTools(server, ctx);
    registerChangeTools(server, ctx);
    registerJobTools(server, ctx);
    registerActionTools(server, ctx);
    registerMediaTools(server, ctx);
    registerRepoTools(server, ctx);
    registerCopyTools(server, ctx);
    registerTailnetTools(server, ctx);
    registerDnsTools(server, ctx);
    registerGiteaTools(server, ctx);
    registerBeszelTools(server, ctx);
    registerFileEditTools(server, ctx);
    registerInventoryTools(server, ctx);
    const bridge = RemnawaveBridge.from(config.remnawaveMcp);
    const engine = new ScenarioEngine(ctx, SCENARIOS, bridge);
    registerScenarioTools(server, ctx, engine);
    registerAllPrompts(server);
    return { server, ctx, engine, bridge };
}
