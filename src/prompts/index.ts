import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

/** Scenario runbooks: each is a prompt that walks the model through the right tools in order. */
export const SCENARIOS: Array<{ name: string; description: string; args?: Record<string, z.ZodTypeAny>; text: (a: Record<string, string | undefined>) => string }> = [
    {
        name: 'morning_check',
        description: 'Daily look at the fleet: health, audit, what changed overnight',
        text: () =>
            [
                '1. fleet_status — summarize: unreachable hosts, crit/warn counts, nodes DISCONNECTED in the panel, certificates under 21 days, pending reboots/security updates.',
                '2. fleet_audit minSeverity:"warn" — group findings by code, most widespread first; for each code say what it means and which tool fixes it.',
                '3. fleet_snapshot reason:"daily" then fleet_changes — list changes since yesterday that are NOT explained by miaActions (manual or unexpected changes first: access/ssh/firewall/listen/files).',
                '4. Finish with a short prioritized action list (do not run write tools without asking).',
            ].join('\n'),
    },
    {
        name: 'node_down',
        description: 'Incident: a node is down / disconnected in the panel / users complain about a location',
        args: { host: z.string().describe('host name (or panel node name)') },
        text: (a) =>
            [
                `Incident on ${a.host}.`,
                `1. host_inspect host:"${a.host}" — reachable over ssh/Tailscale? remnanode container state and restarts, panel node state and lastStatusMessage, certificate, disk, memory, failed units.`,
                `2. If unreachable over ssh: fleet_discover (is it online in the tailnet?) — a host down in both ssh and tailnet is a provider/VM problem: say so and stop.`,
                `3. host_logs host:"${a.host}" source:"remnanode" lines:200 — and grep "error|fail|panic|certificate" in source "remnanode.log".`,
                `4. host_ports host:"${a.host}" — is NODE_PORT (2222) listening, are the inbound ports allowed publicly?`,
                `5. host_net_check target:"${a.host}" check:"tls" to:<REALITY dest of its inbounds> — is the dest reachable/TLS1.3+h2 from the node?`,
                '6. Propose the fix (service_action restart, cert_renew, ufw_rule, disk_cleanup …) with a dry run; apply only after confirmation.',
            ].join('\n'),
    },
    {
        name: 'rolling_update',
        description: 'Update remnanode on all nodes one by one, then OS updates',
        text: () =>
            [
                '1. fleet_status target:"role:remnanode" — every node must be reachable and connected before starting; list exceptions.',
                '2. fleet_snapshot target:"role:remnanode" reason:"before-update".',
                '3. remnanode_update (dry run) — show which nodes are behind Docker Hub and users online per node; ask for confirmation.',
                '4. Apply with the planHash (batch 1: each node must come back connected in the panel before the next).',
                '5. apt_upgrade (dry run) target:"role:remnanode" — show pending packages, flag docker/containerd upgrades; ask before applying (rebootIfRequired only if agreed).',
                '6. fleet_changes target:"role:remnanode" live:true — confirm only the expected changes happened.',
            ].join('\n'),
    },
    {
        name: 'onboard_node',
        description: 'Bring a fresh VPS into the fleet as a remnanode',
        args: { host: z.string().describe('name for the new host'), address: z.string().describe('public IP'), domain: z.string().describe('node domain (A record → IP)') },
        text: (a) =>
            [
                `New node ${a.host} at ${a.address}, domain ${a.domain}.`,
                `1. Check that the A record of ${a.domain} points to ${a.address} (certbot needs it).`,
                `2. fleet_host_edit (dry run): add ${a.host} with bootstrap.address ${a.address}, roles [remnanode], domain ${a.domain}; apply after a yes.`,
                `3. node_bootstrap host:"${a.host}" (dry run) — show what will be installed; apply only after an explicit yes. Follow it with job_status until it finishes (a Tailscale login URL may need the owner).`,
                '4. After the reboot: fleet_audit on the host, then create the node in the panel (mcp-remnawave) and fleet_snapshot to record its baseline.',
            ].join('\n'),
    },
    {
        name: 'security_review',
        description: 'Security posture of the fleet: exposure, access, drift',
        text: () =>
            [
                '1. fleet_audit code:"fw" and code:"ssh" minSeverity:"info" — public ports beyond policy, ufw off, password auth, root login.',
                '2. For each remnanode: host_ports — anything public that should be tailnet-only.',
                '3. fleet_changes section:"access" and section:"ssh" (vs the first snapshot with since) — new users, sudoers, authorized keys, crontabs.',
                '4. host_firewall on the busiest nodes — fail2ban activity, ipset blacklists, MGMT-PORTS.',
                '5. Report concrete findings with the tool call that fixes each.',
            ].join('\n'),
    },
    {
        name: 'weekly_maintenance',
        description: 'Weekly: certificates, geo/blacklist freshness, disks, updates, drift',
        text: () =>
            [
                '1. fleet_audit code:"cert", code:"geo", code:"blacklist", code:"mgmt", code:"disk", code:"apt", code:"reboot", code:"updates".',
                '2. cert_renew / geo_update / blacklist_update / disk_cleanup dry runs for the affected hosts only.',
                '3. apt_upgrade dry run (securityOnly first).',
                '4. fleet_snapshot reason:"weekly"; fleet_changes since 7 days ago — summarize.',
                '5. Ask before applying anything.',
            ].join('\n'),
    },
];

SCENARIOS.push(
    {
        name: 'home_check',
        description: 'Home servers: containers, temperatures, disks, Jellyfin and Tdarr state',
        text: () =>
            [
                '1. fleet_status target:"tag:home" — temperatures (temp column), disks of the media drives, pending updates.',
                '2. fleet_audit target:"tag:home" minSeverity:"warn" — services down (svc.*), temp.high, disk.full.',
                '3. For hosts with Jellyfin: jellyfin_status — who is watching (transcodes!), failed scheduled tasks, libraries being scanned.',
                '4. For hosts with Tdarr: tdarr_status — paused nodes, libraries and their folders.',
                '5. Summarize; propose fixes as dry runs only.',
            ].join('\n'),
    },
    {
        name: 'media_add_folder',
        description: 'Add a folder with new media to Jellyfin and Tdarr on a home server',
        args: { host: z.string().describe('home server'), folder: z.string().describe('folder on the host, e.g. /mnt/media/clips90') },
        text: (a) =>
            [
                `Add ${a.folder} on ${a.host} to the media stack. Dry runs only until the owner confirms.`,
                `1. jellyfin_status host:"${a.host}" and tdarr_status host:"${a.host}" — which library fits (by type and neighbouring folders)? If none fits, propose jellyfin_library_create with optionsFrom a similar library.`,
                `2. jellyfin_library_add_path host:"${a.host}" library:<chosen> path:"${a.folder}" (dry run) — check the container path mapping and the file count it shows.`,
                `3. tdarr_library_add host:"${a.host}" folders:["${a.folder}"] template:<library with the right flow> (dry run) — review the library object, cache/output and overlap warnings.`,
                '4. Show both plans; apply each with its planHash only after an explicit yes.',
            ].join('\n'),
    },
);

export function registerAllPrompts(server: McpServer) {
    for (const s of SCENARIOS) {
        if (s.args) {
            server.prompt(s.name, s.description, s.args as Record<string, z.ZodString>, (a) => ({ messages: [{ role: 'user', content: { type: 'text', text: s.text(a) } }] }));
        } else {
            server.prompt(s.name, s.description, () => ({ messages: [{ role: 'user', content: { type: 'text', text: s.text({}) } }] }));
        }
    }
}
