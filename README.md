# mia-assist

An MCP server and CLI (`mia`) that runs a fleet of Linux servers from your own machine over the
system `ssh` and Tailscale — "a small Ansible you can talk to". From Claude Code (or straight from the
terminal) you see the state of every host, what changed on it since last time, and you run routine
operations: always as a dry run first, then an explicit apply of exactly that plan, one host at a time,
with a journal.

It was built for a fleet of proxy nodes running [Remnawave](https://github.com/remnawave) / Xray, but
most of it is generic: any Ubuntu/Debian host with docker, systemd, UFW and fail2ban, plus home
servers (compose/systemd services, Jellyfin and Tdarr through their APIs). The Remnawave panel itself
is only *read* here (to match hosts to panel nodes and show who is connected); panel changes belong to
a separate MCP server ([mcp-remnawave](https://github.com/akadorkin/mcp-remnawave)), which the
runbooks can drive step by step.

| | |
|---|---|
| Runtime | Node.js 22+, the system `ssh`, Tailscale on the machine that runs it (optional) |
| Hosts | Ubuntu 22.04 / 24.04 (the audit baseline assumes nodes built with [vps-edge-run.sh](https://github.com/akadorkin/remnanode-install-script); override it in `policy`) |
| Tools | 63 MCP tools (28 read-only) — full list in [docs/TOOLS.md](docs/TOOLS.md) |
| Prompts | 8 MCP prompts (`morning_check`, `node_down`, `rolling_update`, …) |
| Runbooks | `xray_rules`, `fleet_update` (engine for your own in `src/scenarios`) |
| UI | MCP (English tool descriptions), terminal console and a local web page (**Russian** UI text) |

## Safety model

This is the point of the project. Nothing changes a host unless you saw the exact plan and said yes.

- **Two-step plan → apply.** Every tool that changes something, called without `apply`, returns the
  exact plan per host (commands, packages, files, current state) and a `planHash`. Only the same call
  with `apply: true` and that `planHash` runs it. The hash covers the inputs *and* a fingerprint of the
  live state: if the host changed between plan and apply, the apply is refused and a fresh plan is
  shown. A `planHash` is single-use; two concurrent applies of one plan cannot both run.
- **Rolling, one host at a time.** Disruptive actions (restarts, reboots, upgrades, firewall) default to
  `batch: 1`: each host must come back (ssh answers, the service runs, the panel node is connected)
  before the next one starts; the first failure stops the rollout. Cheap actions (`host_exec`,
  `disk_cleanup`, `cert_renew`, geo/blacklist updates) default to 10 at a time; pass `batch: 1` to go slower.
- **Blockers and warnings.** Plans carry blockers (the host is unreachable, a busy runner, a non-apt
  system…) and warnings (users online on a node you are about to restart). Irreversible actions in the
  console must be confirmed by typing the host count or name, not by Enter.
- **Journal.** Every apply is written to a local journal (`journal_list`) with the plan, the result per
  host and the time; snapshots (`fleet_snapshot`, `fleet_changes`) keep a history of what changed on
  each host, including changes made by hand outside mia.
- **Read-only mode.** `MIA_READONLY=true` makes every write tool refuse to apply. Start with it.
- **Secrets stay local.** ssh keys, API keys (`~/.config/mia/secrets.env`, mode 600, `op://` references
  allowed) and the journal stay on your machine. Every known secret value and common secret shapes
  (tokens, WireGuard/PEM keys, subscription links, shadow hashes) are masked in all output.
  Remote scripts are sent over stdin; inputs go through quoted env vars, never interpolated into code.
- **No automatic reboots.** Upgrades report which hosts want a reboot; rebooting is a separate, explicit action.
- **Web UI binds to 127.0.0.1 only**, with a per-run token cookie, a Host check and a custom header
  required on anything that starts work.

## Install

```bash
git clone https://github.com/akadorkin/mia-assist.git && cd mia-assist
npm install && npm run build

mkdir -p ~/.config/mia && cp fleet.example.yaml ~/.config/mia/fleet.yaml   # then edit it
node dist/cli.js --demo        # a made-up fleet of 7 hosts: nothing leaves this machine
MIA_READONLY=true node dist/cli.js status
```

`npm link` gives you a plain `mia` command. Optional API keys are stored once with
`mia secrets set TAILSCALE_API_KEY` (values are never echoed); see [.env.example](.env.example) for
every setting.

## Plug into Claude Code

```bash
claude mcp add mia -s user \
  -e MIA_INVENTORY=$HOME/.config/mia/fleet.yaml \
  -e MIA_READONLY=true \
  -e REMNAWAVE_BASE_URL=https://panel.example.com \
  -e REMNAWAVE_API_TOKEN=<token> \
  -- node /path/to/mia-assist/dist/cli.js mcp
```

Then ask: "what's wrong with the fleet?", "why did nl-1 drop out of the panel?", "update remnanode on
all nodes one by one", "what changed on the servers this week?". Remove `MIA_READONLY` once the status
and audit tell the truth about your hosts.

## Inventory example

`~/.config/mia/fleet.yaml` (full annotated version: [fleet.example.yaml](fleet.example.yaml); the real
file is git-ignored):

```yaml
defaults:
  user: ops                   # ssh user with NOPASSWD sudo

policy:                       # audit baseline, global or per host
  publicPorts: ["80/tcp", "443/tcp", "443/udp"]
  certWarnDays: 21

groups:
  eu: [nl-1, de-1]
  hands-off: [nas]            # fleet_update never touches these

hosts:
  nl-1:
    address: nl-1             # Tailscale MagicDNS name, tailnet IP or ~/.ssh/config alias
    roles: [remnanode]        # edge baseline + remnanode/certbot/geo checks
    domain: nl1.example.com
    tags: [prod]
    bootstrap: { address: 203.0.113.10, user: root }   # used before Tailscale exists
  panel:
    address: panel
    roles: [panel]
    services:
      - name: remnawave
        compose: /opt/remnawave/docker-compose.yml
  home:
    address: home
    roles: [docker]
    apps:
      jellyfin: { url: http://127.0.0.1:8096, apiKey: env:JELLYFIN_API_KEY, container: jellyfin }
```

Targets everywhere: `all | host | glob | group | role:remnanode | tag:x`, comma-separated, `!x` excludes.
`fleet_discover` cross-checks the inventory with the tailnet and the panel and prints ready YAML for
missing hosts; `host_services_discover` does the same for services on one host.

## Tools

Generated by `npm run docs:tools` into [docs/TOOLS.md](docs/TOOLS.md). By area (RO = read-only):

| Area | Tools |
|---|---|
| Fleet | `fleet_hosts` RO, `fleet_discover` RO, `fleet_status` RO, `fleet_audit` RO, `fleet_host_edit` |
| One host | `host_inspect`, `host_logs`, `host_ports`, `host_firewall`, `host_docker`, `host_file_read`, `host_net_check`, `host_connections` (all RO), `host_exec`, `host_file_edit`, `host_copy` |
| History | `fleet_snapshot`, `fleet_changes`, `snapshots_list`, `journal_list`, `job_status` (all RO) |
| Actions | `service_action`, `remnanode_update`, `cert_renew`, `geo_update`, `blacklist_update`, `updates_policy`, `apt_upgrade`, `host_reboot`, `disk_cleanup`, `tuning_status` RO, `tuning_apply`, `ufw_rule`, `fail2ban_unban`, `node_bootstrap` |
| Scheduling | `fleet_schedule` RO, `schedule_toggle`, `cron_logging` |
| Your scripts | `repo_script` (run a script from a local repo checkout, the plan shows commit and file hash) |
| Network | `ru_probe` RO (reachability from a vantage host inside a censored network, per ISP, with a datacenter control), `tailnet_devices` RO, `tailnet_device_remove`, `tailnet_join`, `dns_records` RO, `dns_change` (Cloudflare) |
| Integrations | `gitea_runners` RO, `gitea_runner_register`, `gitea_runner_remove`, `beszel_systems` RO, `beszel_system_edit` |
| Home media | `host_services_discover` RO, `jellyfin_status` RO, `jellyfin_library_add_path`, `jellyfin_library_create`, `jellyfin_scan`, `jellyfin_task_run`, `tdarr_status` RO, `tdarr_library_add`, `tdarr_scan`, `tdarr_pause` |
| Runbooks | `scenario_list` RO, `scenario_start`, `scenario_step` |

## Runbooks

A runbook is an ordered, resumable list of steps (`src/core/scenario.ts`): `check` (read-only, may
poll), `mia` (a write tool: dry run → planHash → apply), `panel` (an mcp-remnawave tool, same two-step
gate), `manual` (something only you can do, answered with "done"), `inventory` (a fleet.yaml edit that
keeps layout and comments) and `local` (git/files in your checkouts, shown before they run). Checks run
by themselves; every change waits for an explicit apply. Runs are saved and can be continued later. A
failed gate check cannot be skipped past: only its rollback step runs.

Included:

- `fleet_update` — security (or all) updates host by host, canary first; after each host: back over the
  tailnet, `dpkg --audit` clean, panel node connected; never a reboot, never the `hands-off` group.
- `xray_rules` — add/remove domains or IPs in a routing rule, change an outbound, insert a rule, one
  config profile at a time through mcp-remnawave; each profile's nodes must reconnect before the next.

The original private version also had runbooks for adding a node end to end, moving an ingress to a new
machine, removing a node and DR failover. They were tied to one specific fleet (its repos, monitoring
and load balancer layout) and were **not** included. The helpers they used (`dnsStep`, `ruGateStep`,
`tailnetOf`, `gitCommit` in `src/scenarios/common.ts`) are here for writing your own.

## Configuration

Environment (or `~/.config/mia/secrets.env`, managed by `mia secrets`):

| Variable | Purpose |
|---|---|
| `MIA_INVENTORY` | path of fleet.yaml (default `~/.config/mia/fleet.yaml`) |
| `MIA_READONLY` | `true` = no applies |
| `MIA_STATE_DIR` | journal, snapshots, oversized outputs (default `~/.local/state/mia`) |
| `MIA_SSH_OPTIONS`, `MIA_CONCURRENCY`, `MIA_SSH_REUSE` | ssh behaviour |
| `REMNAWAVE_BASE_URL`, `REMNAWAVE_API_TOKEN` | panel, read-only use |
| `MIA_REMNAWAVE_MCP` | command that starts mcp-remnawave for panel steps of runbooks |
| `MIA_REPOS`, `MIA_GIT_AUTHOR` | local checkouts for `repo_script` / runbook `local` steps |
| `MIA_PROBE_FROM`, `MIA_PROBE_IFACES`, `MIA_PROBE_CONTROL` | `ru_probe` vantage host, its ISP interfaces (`wan0=ISP-A,wan1=ISP-B`), datacenter control host |
| `TAILSCALE_API_KEY`, `CLOUDFLARE_API_TOKEN`, `GITEA_URL`/`GITEA_TOKEN`, `BESZEL_URL`/… | optional integrations |

## Also in the box

- `mia` — an interactive terminal console (menus, search, plan → Enter) and `mia web` — the same as a
  local page on 127.0.0.1 (`mia web --demo` to try it). Both are in Russian.
- `mia sessions-digest` — reads your local Claude Code transcripts (`~/.claude/projects`, secrets
  masked) and writes a per-session digest plus a summary of hosts, IPs, domains and containers seen, to
  bootstrap an inventory. Local only.

## Development

```bash
npm run build      # tsc --noEmit + tsup
npm test           # node:test via tsx (3 tests are skipped on macOS: they need GNU coreutils)
npm run docs:tools # regenerate docs/TOOLS.md after changing a tool
```

The lockfile is not committed; `npm install` resolves it.

## Honest notes

- It is a personal ops tool published as is. The defaults and the audit baseline (MGMT-PORTS iptables
  chain, ipset blacklists, beszel-agent, unattended security updates, no auto-reboots) reflect how the
  original fleet was built; adjust `policy` for yours.
- `node_bootstrap` and `tuning_apply` run public install scripts pinned by URL
  (`MIA_EDGE_SCRIPT_URL`, `MIA_TUNING_SCRIPT_URL`); pin them to a commit you have reviewed.
- Remote commands run as root via sudo on your hosts. Read the plan.

## License

MIT, see [LICENSE](LICENSE).

## Кратко по-русски

`mia` — MCP-сервер и консоль для управления флотом Linux-серверов по ssh/Tailscale (ноды
Remnawave/Xray, панель, домашние серверы). Всё, что меняет сервер, работает в два шага: холостой
прогон с точным планом и `planHash`, затем `apply` именно этого плана; опасные действия — по одному
хосту с проверкой, что он вернулся; всё пишется в журнал, снимки показывают ручные изменения. Начинать
стоит с `MIA_READONLY=true`. Консоль и веб-страница на русском, описания MCP-инструментов на английском.
Ранбуки, завязанные на конкретный флот (новая нода, перенос ингресса, вывод ноды, DR), в публичную
версию не вошли.
