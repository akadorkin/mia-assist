# shellcheck shell=bash
# mia probe: collects the state of one host in a single ssh round-trip.
# Output: one record per line, "<key>\t<base64 value>". Every probe is best effort:
# a missing tool or file yields an empty value, never a failed run.
#
# Inputs (exported by the caller):
#   MIA_MODE      quick | full   (full adds what snapshots need: packages, files, keys …)
#   MIA_SERVICES  lines "name|compose|container|unit"
#   MIA_FILES     lines of paths / globs whose content is tracked (full mode)

set +e
MODE="${MIA_MODE:-quick}"

emit() { printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | base64 -w0 2>/dev/null || printf '%s' "$2" | base64 | tr -d '\n')"; }
has() { command -v "$1" >/dev/null 2>&1; }

emit probe_version "2"
emit mode "$MODE"
emit whoami "$(id -un)"
emit hostname "$(hostname 2>/dev/null)"
emit os "$( . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
emit kernel "$(uname -r)"
emit arch "$(uname -m)"
emit now "$(date +%s)"
emit uptime "$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
emit loadavg "$(cat /proc/loadavg 2>/dev/null)"
emit cpus "$(nproc 2>/dev/null)"
emit meminfo "$(grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null)"
# temperatures: thermal zones (CPU/SoC, Raspberry Pi) and hwmon sensors (drives with drivetemp, nvme, boards)
out=""
for z in /sys/class/thermal/thermal_zone*; do
  [ -r "$z/temp" ] || continue
  out="$out$(cat "$z/type" 2>/dev/null) $(cat "$z/temp" 2>/dev/null)
"
done
for t in /sys/class/hwmon/hwmon*/temp*_input; do
  [ -r "$t" ] || continue
  d="$(dirname "$t")"; l="${t%_input}_label"
  out="$out$(cat "$d/name" 2>/dev/null)/$(cat "$l" 2>/dev/null || basename "${t%_input}") $(cat "$t" 2>/dev/null)
"
done
emit temps "$out"
# -l: only local filesystems — a CIFS/NFS share (a NAS mount of another host's disk) is counted where the disk lives
emit df "$(df -lPTk -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null | tail -n +2)"

if [ -f /var/run/reboot-required ]; then
  emit reboot_required "$(cat /var/run/reboot-required.pkgs 2>/dev/null | sort -u | tr '\n' ' ')"
  emit reboot_required_flag "yes"
fi
if has apt; then
  emit apt_upgradable "$(apt list --upgradable 2>/dev/null | tail -n +2)"
  emit apt_last_update "$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -c %Y /var/cache/apt/pkgcache.bin 2>/dev/null)"
fi

# ---------------------------------------------------------------- systemd
UNITS="ssh sshd docker tailscaled fail2ban node_exporter beszel-agent ufw ipset-load cron haproxy systemd-resolved systemd-timesyncd chrony update-roscomvpn-geo.timer update-roscomvpn-geo.service unattended-upgrades apt-daily-upgrade.timer apt-daily.timer"
if has systemctl; then
  out=""
  for u in $UNITS; do
    load="$(systemctl show -p LoadState --value "$u" 2>/dev/null)"
    en="$(systemctl is-enabled "$u" 2>/dev/null)"
    [ "$load" = "not-found" ] && continue
    [ "$en" = "not-found" ] && continue
    [ -z "$load$en" ] && continue
    out="$out$u|$(systemctl is-active "$u" 2>/dev/null)|$en
"
  done
  emit units "$out"
  emit failed_units "$(systemctl list-units --failed --no-legend --plain 2>/dev/null | awk '{print $1}')"
  emit geo_service "$(systemctl show update-roscomvpn-geo.service -p Result -p ExecMainStatus -p ExecMainExitTimestamp 2>/dev/null)"
  emit geo_service2 "$(systemctl show update-roscomvpn-dat.service -p Result -p ExecMainStatus -p ExecMainExitTimestamp 2>/dev/null)"
  emit timedate "$(timedatectl show -p NTPSynchronized -p Timezone 2>/dev/null)"
fi

# ---------------------------------------------------------------- network / firewall
has ufw && emit ufw "$(ufw status verbose 2>/dev/null)"
has ss && emit listen "$(ss -H -lntup 2>/dev/null)"
has ip && emit ifaces "$(ip -o link show 2>/dev/null | awk -F': ' '{sub(/@.*/,"",$2); print $2}')"
if has sshd; then
  emit sshd "$(sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|x11forwarding|maxauthtries) ')"
fi
if has fail2ban-client; then
  jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' ')"
  out=""
  for j in $jails; do
    st="$(fail2ban-client status "$j" 2>/dev/null)"
    cur="$(printf '%s\n' "$st" | sed -n 's/.*Currently banned:[[:space:]]*//p' | head -n1)"
    tot="$(printf '%s\n' "$st" | sed -n 's/.*Total banned:[[:space:]]*//p' | head -n1)"
    out="$out$j ${cur:-0} ${tot:-0}
"
  done
  emit fail2ban "$out"
fi
emit sysctl "$(sysctl -e net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_count fs.file-max fs.nr_open net.core.somaxconn net.ipv4.tcp_fastopen net.core.rmem_max net.core.wmem_max vm.swappiness 2>/dev/null)"
emit tuning_backups "$(ls -1d /root/edge-tuning-backup-* 2>/dev/null | tail -n 3)"
emit resolv "$(grep -E '^(DNS|FallbackDNS)=' /etc/systemd/resolved.conf 2>/dev/null)"

# fleet firewall: ipset blacklists (ufw-blacklist.sh + ipset-load) and the MGMT-PORTS chain
if has ipset; then
  emit ipsets "$(ipset list -t 2>/dev/null | awk '/^Name:/{n=$2} /^Number of entries:/{print n, $4}')"
fi
[ -f /etc/cron.d/ufw-blacklist ] && emit blacklist_cron "$(grep -Ev '^\s*(#|$)' /etc/cron.d/ufw-blacklist | head -n 3)"
[ -f /usr/local/bin/ufw-blacklist.sh ] && emit blacklist_script "$(stat -c %Y /usr/local/bin/ufw-blacklist.sh 2>/dev/null)"
if has iptables; then
  if iptables -S MGMT-PORTS >/dev/null 2>&1; then
    emit mgmt_chain "$(iptables -S MGMT-PORTS 2>/dev/null | wc -l)"
    emit mgmt_jump "$(iptables -S INPUT 2>/dev/null | grep -c -- '-j MGMT-PORTS')"
  fi
  # ports INPUT sends through a guard chain (MGMT-PORTS / ADMIN-PORTS: tailnet + home only, then DROP) ahead of ufw
  guards=""
  for ch in MGMT-PORTS ADMIN-PORTS; do
    iptables -S "$ch" 2>/dev/null | grep -q -- '-j DROP' || continue
    guards="$guards $(iptables -S INPUT 2>/dev/null | sed -n "s/.*--dport \([0-9:]*\) .*-j $ch\b.*/\1/p" | tr '\n' ' ')"
  done
  emit guard_ports "$guards"
fi
[ -f /etc/mgmt-ports.list ] && emit mgmt_list "$(grep -Ev '^\s*(#|$)' /etc/mgmt-ports.list | tr '\n' ' ')"
# legacy (vps-edge-run.sh before August 2026): rugov nftables chain
if has nft && nft list chain inet filter rugov_input >/dev/null 2>&1; then emit rugov_chain "yes"; fi
# automatic updates / reboots (fleet policy: off, the owner decides)
if has apt-config; then
  emit apt_auto "$(apt-config dump 2>/dev/null | grep -E '^(APT::Periodic::Unattended-Upgrade|APT::Periodic::Update-Package-Lists|Unattended-Upgrade::Automatic-Reboot) ' | sed 's/;$//')"
  emit apt_origins "$(apt-config dump 2>/dev/null | grep -E '^Unattended-Upgrade::(Allowed-Origins|Origins-Pattern):: ' | sed 's/^[^"]*"//; s/";$//')"
  emit uu_installed "$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -c 'install ok installed')"
fi

# ---------------------------------------------------------------- tailscale
if has tailscale; then
  ts="$(tailscale status --json --peers=false 2>/dev/null)"
  [ -z "$ts" ] && ts="$(tailscale status --json 2>/dev/null | head -c 200000)"
  emit tailscale "$ts"
  emit tailscale_version "$(tailscale version 2>/dev/null | head -n1)"
fi

# ---------------------------------------------------------------- docker
if has docker; then
  emit docker_version "$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  emit compose_version "$(docker compose version --short 2>/dev/null)"
  emit docker_ps "$(docker ps -a --no-trunc --format '{{.Names}}	{{.Image}}	{{.State}}	{{.Status}}' 2>/dev/null)"
  ids="$(docker ps -aq 2>/dev/null)"
  if [ -n "$ids" ]; then
    emit docker_inspect "$(docker inspect --format '{{.Name}}	{{.Image}}	{{.Config.Image}}	{{.State.StartedAt}}	{{.RestartCount}}	{{.State.Health}}' $ids 2>/dev/null)"
  fi
  imgs="$(docker ps -a --format '{{.Image}}' 2>/dev/null | sort -u)"
  if [ -n "$imgs" ]; then
    out=""
    for i in $imgs; do
      out="$out$i	$(docker image inspect --format '{{.Id}}	{{join .RepoDigests ","}}	{{.Created}}' "$i" 2>/dev/null)
"
    done
    emit docker_images_used "$out"
  fi
fi

# ---------------------------------------------------------------- remnanode specifics
if [ -f /opt/remnanode/docker-compose.yml ]; then
  c=/opt/remnanode/docker-compose.yml
  emit remnanode_compose "image=$(grep -E '^\s*image:' "$c" | head -n1 | sed 's/.*image:[[:space:]]*//')
node_port=$(grep -E 'NODE_PORT=' "$c" | head -n1 | sed 's/.*NODE_PORT=//' | tr -d "\"' ")
secret_key=$(grep -Eq 'SECRET_KEY=.+' "$c" && echo present || echo missing)
geo_volumes=$(grep -c 'roscomvpn-' "$c")
cert_volume=$(grep -c '/opt/certbot/certs' "$c")
network_host=$(grep -c 'network_mode: host' "$c")"
fi
emit geo_files "$(stat -c '%n %Y %s' /opt/remnanode/roscomvpn-*.dat 2>/dev/null)"
# update-roscomvpn-geo.sh v2 (2026-10-01) writes its own state for node_exporter: last run, failures, which files xray uses
for d in /var/lib/node_exporter/textfile /var/lib/node_exporter/textfile_collector /var/lib/prometheus/node-exporter; do
  [ -f "$d/roscomvpn_geo.prom" ] && { emit geo_metrics "$(grep -E '^roscomvpn_geo_(last_run_timestamp_seconds|last_run_failed|file_used)' "$d/roscomvpn_geo.prom")"; break; }
done
out=""
for f in /opt/certbot/certs/live/*/fullchain.pem; do
  [ -f "$f" ] || continue
  end="$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2)"
  out="$out$(basename "$(dirname "$f")")	$(date -d "$end" +%s 2>/dev/null)	$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')	$(openssl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')
"
done
emit certs "$out"
emit remnanode_logs "$(ls -l --time-style=+%s /var/log/remnanode/ 2>/dev/null | tail -n +2 | awk '{print $NF, $5, $6}')"

# ---------------------------------------------------------------- inventory services
if [ -n "$MIA_SERVICES" ]; then
  out=""
  while IFS='|' read -r name compose container unit; do
    [ -z "$name" ] && continue
    state=""
    if [ -n "$compose" ]; then
      if [ -f "$compose" ]; then
        ps="$(docker compose -f "$compose" ps -a --format '{{.Service}}:{{.State}}' 2>/dev/null | tr '\n' ' ')"
        state="compose=${ps:-none}"
      else
        state="compose=missing-file"
      fi
    fi
    if [ -n "$container" ] && has docker; then
      cs="$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null)"
      state="$state container=${cs:-absent}"
    fi
    if [ -n "$unit" ] && has systemctl; then
      load="$(systemctl show -p LoadState --value "$unit" 2>/dev/null)"
      if [ "$load" = "not-found" ] || [ -z "$load" ]; then
        state="$state unit=absent"
      else
        state="$state unit=$(systemctl is-active "$unit" 2>/dev/null)/$(systemctl is-enabled "$unit" 2>/dev/null)"
      fi
    fi
    out="$out$name	$state
"
  done <<EOF_SERVICES
$MIA_SERVICES
EOF_SERVICES
  emit services "$out"
fi

# ---------------------------------------------------------------- full mode: what snapshots track
if [ "$MODE" = "full" ]; then
  has dpkg-query && emit packages "$(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null)"
  has snap && emit snaps "$(snap list 2>/dev/null | tail -n +2 | awk '{print $1"\t"$2}')"
  has systemctl && emit enabled_units "$(systemctl list-unit-files --state=enabled --no-legend --plain 2>/dev/null | awk '{print $1}')"
  has docker && emit docker_images "$(docker images --digests --format '{{.Repository}}:{{.Tag}}	{{.Digest}}	{{.ID}}' 2>/dev/null)"
  has nft && emit nft_chains "$(nft list chains 2>/dev/null | grep -E '^[[:space:]]*(table|chain) ' | sed 's/[[:space:]]*{.*//; s/^[[:space:]]*//')"
  emit users "$(getent passwd 2>/dev/null | awk -F: '$3==0 || $3>=1000 {print $1":"$3":"$7}')"
  emit sudo_group "$(getent group sudo 2>/dev/null | cut -d: -f4)"
  out=""
  for home in /root /home/*; do
    f="$home/.ssh/authorized_keys"
    [ -f "$f" ] || continue
    out="$out$(ssh-keygen -lf "$f" 2>/dev/null | awk -v h="$home" '{c=""; for(i=3;i<NF;i++) c=c (c?" ":"") $i; print h"\t"$2"\t"c"\t"$NF}')
"
  done
  emit authorized_keys "$out"
  emit crontabs "$(for u in $(cut -d: -f1 /etc/passwd); do l="$(crontab -l -u "$u" 2>/dev/null | grep -Ev '^\s*(#|$)')"; [ -n "$l" ] && printf '%s\n' "$l" | sed "s/^/$u: /"; done)"

  # tracked files: content if small text, else hash only
  if [ -n "$MIA_FILES" ]; then
    printf '%s\n' "$MIA_FILES" | while read -r pat; do
      [ -z "$pat" ] && continue
      for f in $pat; do
        [ -f "$f" ] || continue
        size="$(stat -c %s "$f" 2>/dev/null)"
        sum="$(sha256sum "$f" 2>/dev/null | cut -c1-16)"
        if [ "${size:-0}" -le 65536 ] && grep -Iq . "$f" 2>/dev/null; then
          emit "file:$f" "sha=$sum size=$size
$(cat "$f")"
        else
          emit "file:$f" "sha=$sum size=$size
(binary or large: content not tracked)"
        fi
      done
    done
  fi
fi

emit "done" "1"
