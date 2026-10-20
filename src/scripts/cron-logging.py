#!/usr/bin/env python3
"""cron_logging on one host (mia, 2026-10-01): every cron job writes its output to a log file, and every
such log is rotated. MODE=plan prints what would change as JSON; MODE=apply writes it (copies of every
touched file go to /root/mia-backup first) and checks logrotate. Stock OS cron files are left alone.

- a line that already appends to a file (>> /path, > /path, &>> /path) keeps it; the file joins rotation
  unless some logrotate config already covers it
- output to /dev/null or nowhere → >> /var/log/cron/<job>.log 2>&1
- a line piping into logger keeps going to syslog (journald / rsyslog rotate it)
- (2026-10-09) every line runs through /usr/local/sbin/mia-cronrun <id> '<command>': the command itself is
  unchanged, the wrapper records start, end and exit code in /var/lib/mia-cron/<id>.json so fleet_schedule
  shows a result for cron jobs like it does for timers. Already wrapped lines are left as they are.
"""
import fnmatch, glob, grp, hashlib, json, os, re, shutil, subprocess, sys, time

MODE = os.environ.get("MODE", "plan")
LOGDIR = "/var/log/cron"
ROT = "/etc/logrotate.d/cron-jobs"
WRAP = "/usr/local/sbin/mia-cronrun"
STATEDIR = "/var/lib/mia-cron"
WRAPPER = r"""#!/bin/sh
# mia-cronrun <id> <command> (mia cron_logging, 2026-10-09): runs one cron job's command with the cron shell and
# records when it started, when it ended and its exit code in /var/lib/mia-cron/<id>.json — fleet_schedule reads it.
# The command keeps its own output redirection; this wrapper writes nothing to stdout/stderr itself.
id="$1"; shift
d=/var/lib/mia-cron
s=$(date +%s)
printf '{"start":%s,"pid":%s,"user":"%s"}\n' "$s" "$$" "$(id -un)" > "$d/.$id.$$" 2>/dev/null && mv -f "$d/.$id.$$" "$d/$id.json" 2>/dev/null
${SHELL:-/bin/sh} -c "$1"
rc=$?
printf '{"start":%s,"end":%s,"rc":%s,"user":"%s"}\n' "$s" "$(date +%s)" "$rc" "$(id -un)" > "$d/.$id.$$" 2>/dev/null && mv -f "$d/.$id.$$" "$d/$id.json" 2>/dev/null
exit $rc
"""
STAMP = time.strftime("%Y%m%d-%H%M%S")
SYSTEM_FILES = re.compile(r"/(e2scrub_all|popularity-contest|sysstat|php|\.placeholder|anacron|mdadm|zfsutils-linux|certbot|mia-test)$")
ENV_LINE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=")
SCHED = re.compile(r"^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+")
TO_FILE = re.compile(r"(?:&>>|>>|&>|(?<![0-9&])>)\s*(\S+)")
DEVNULL = re.compile(r"\s*(?:\d?>>?\s*/dev/null|&>>?\s*/dev/null)(?:\s+2>&1)?|\s*2>&1\s+>\s*/dev/null")


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "job"


def split(line, with_user):
    m = SCHED.match(line)
    if not m:
        return None
    rest = line[m.end():]
    user = ""
    if with_user:
        u = re.match(r"(\S+)\s+", rest)
        if not u:
            return None
        user, rest = u.group(1), rest[u.end():]
    return m.group(1), user, rest


def target_log(cmd):
    """the file a command already writes its output to (not /dev/null), else None"""
    for m in TO_FILE.finditer(cmd):
        p = m.group(1).strip("'\"")
        if p.startswith("/") and p != "/dev/null" and not p.startswith("/dev/"):
            return p
    return None


def rewrite(cmd, log):
    """command → same command with its output appended to `log`"""
    c = DEVNULL.sub("", cmd).rstrip()
    # cron treats % as newline unless escaped — the redirection goes before an unescaped % (stdin data)
    i = re.search(r"(?<!\\)%", c)
    tail = ""
    if i:
        c, tail = c[: i.start()].rstrip(), c[i.start():]
    return f"{c} >> {log} 2>&1{(' ' + tail) if tail else ''}"


def wrap(cmd, job_id):
    """command → mia-cronrun <id> '<command>' (an unescaped % starts cron's stdin data: it stays outside)"""
    i = re.search(r"(?<!\\)%", cmd)
    body, tail = (cmd[: i.start()].rstrip(), cmd[i.start():]) if i else (cmd, "")
    q = "'" + body.replace("'", "'\\''") + "'"
    return f"{WRAP} {job_id} {q}{(' ' + tail) if tail else ''}"


def covered_by_logrotate(path):
    """some config already rotates this exact file (or a glob matching it)"""
    for f in ["/etc/logrotate.conf"] + glob.glob("/etc/logrotate.d/*"):
        if f == ROT or not os.path.isfile(f):
            continue
        try:
            txt = open(f, errors="replace").read()
        except OSError:
            continue
        for tok in re.findall(r"(/[^\s{]+)", txt):
            if tok == path or ("*" in tok and fnmatch.fnmatch(path, tok)):
                return f
    return None


def sources():
    out = []
    for f in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")):
        if os.path.isfile(f) and not SYSTEM_FILES.search(f):
            out.append(("file", f, None))
    for u in sorted(set(["root"] + (os.listdir("/var/spool/cron/crontabs") if os.path.isdir("/var/spool/cron/crontabs") else []))):
        r = subprocess.run(["crontab", "-l", "-u", u], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            out.append(("crontab", u, r.stdout))
    return out


changes, keep, rotate, skipped = [], [], set(), []
edits = {}  # source → new text
for kind, name, text in sources():
    raw = open(name, errors="replace").read() if kind == "file" else text
    lines = raw.split("\n")
    with_user = kind == "file"
    base = slug(os.path.basename(name) if kind == "file" else f"user-{name}")
    n = 0
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith("#") or ENV_LINE.match(s):
            continue
        sp = split(s, with_user)
        if not sp:
            continue
        sched, user, cmd = sp
        n += 1
        if name == "/etc/crontab" and re.search(r"run-parts|anacron|cron\.(hourly|daily|weekly|monthly)", cmd):
            continue
        where = name if kind == "file" else f"crontab -u {name}"
        wrapped = cmd.startswith(WRAP + " ")
        if re.search(r"\|\s*(/usr/bin/)?(logger|systemd-cat)\b", cmd):
            log, final = "syslog (logger)", cmd
        elif target_log(cmd):
            log = target_log(cmd)
            rotate.add(log)
            final = cmd
        else:
            log = f"{LOGDIR}/{base}{'-' + str(n) if n > 1 else ''}.log"
            final = rewrite(cmd, log)
            rotate.add(log)
        if not wrapped:
            job_id = f"{base}-{hashlib.sha1((sched + ' ' + cmd).encode()).hexdigest()[:6]}"
            final = wrap(final, job_id)
        if final == cmd:
            keep.append({"where": where, "cmd": cmd, "log": log})
            continue
        new = line.replace(cmd, final, 1) if cmd in line else line
        if new == line:
            skipped.append({"where": where, "line": s, "why": "не удалось переписать"})
            continue
        changes.append({"where": where, "before": s, "after": new.strip(), "log": log})
        lines[i] = new
    if any(c["where"] == (name if kind == "file" else f"crontab -u {name}") for c in changes):
        edits[(kind, name)] = "\n".join(lines)

own = sorted(p for p in rotate if p.startswith(LOGDIR + "/"))
others = sorted(p for p in rotate if not p.startswith(LOGDIR + "/"))
covered = {p: covered_by_logrotate(p) for p in others}
extra = [p for p in others if not covered[p]]
# group of /var/log: syslog on rsyslog hosts, root (or adm) where there is no rsyslog
try:
    VARLOG_GROUP = grp.getgrgid(os.stat("/var/log").st_gid).gr_name
except (KeyError, OSError):
    VARLOG_GROUP = "root"
rot_text = (
    "# mia cron_logging (2026-10-01): логи задач cron. Перегенерируется mia — правки руками затрутся.\n"
    "# copytruncate: задачи держат файл открытым на время прогона. su root <группа /var/log>: иначе logrotate откажется.\n"
    + "".join(f"{p}\n" for p in ([f"{LOGDIR}/*.log"] if own or os.path.isdir(LOGDIR) else []) + extra)
    + "{\n    su root " + VARLOG_GROUP + "\n    weekly\n    rotate 8\n    maxsize 50M\n    compress\n    delaycompress\n    missingok\n    notifempty\n    copytruncate\n}\n"
)
cur_rot = open(ROT).read() if os.path.exists(ROT) else ""
result = {
    "change": changes,
    "keep": keep,
    "skipped": skipped,
    "wrapper": {"path": WRAP, "install": (open(WRAP).read() if os.path.exists(WRAP) else "") != WRAPPER},
    "rotation": {"new": own, "add": extra, "alreadyRotated": {p: c for p, c in covered.items() if c}, "rewrite": cur_rot != rot_text and bool(own or extra)},
}

if MODE == "apply":
    os.makedirs("/root/mia-backup", exist_ok=True)
    os.makedirs(LOGDIR, mode=0o755, exist_ok=True)
    # the wrapper and its state dir go first: a rewritten line must never point at a missing wrapper
    os.makedirs(STATEDIR, exist_ok=True)
    os.chmod(STATEDIR, 0o1777)  # personal crontabs run as their user: sticky like /tmp
    if result["wrapper"]["install"]:
        with open(WRAP + ".tmp", "w") as fh:
            fh.write(WRAPPER)
        os.chmod(WRAP + ".tmp", 0o755)
        os.replace(WRAP + ".tmp", WRAP)
    # the wrapper must run and leave a mark before any line points at it
    chk = subprocess.run([WRAP, "mia-selftest", "exit 0"], capture_output=True, text=True, env={**os.environ, "SHELL": "/bin/sh"})
    try:
        mark = json.load(open(f"{STATEDIR}/mia-selftest.json"))
        result["wrapperCheck"] = "ok" if chk.returncode == 0 and mark.get("rc") == 0 else f"rc={chk.returncode} mark={mark}"
        os.remove(f"{STATEDIR}/mia-selftest.json")
    except Exception as e:  # noqa: BLE001
        result["wrapperCheck"] = f"нет отметки: {e}"
    if result["wrapperCheck"] != "ok":
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    for (kind, name), txt in edits.items():
        if kind == "file":
            shutil.copy2(name, f"/root/mia-backup/{name.replace('/', '_')}.{STAMP}")
            with open(name, "w") as fh:
                fh.write(txt)
        else:
            subprocess.run(["sh", "-c", f"crontab -l -u {name} > /root/mia-backup/crontab-{name}.{STAMP}"], check=False)
            subprocess.run(["crontab", "-u", name, "-"], input=txt, text=True, check=True)
    if result["rotation"]["rewrite"]:
        if cur_rot:
            os.makedirs("/root/mia-backup", exist_ok=True)
            shutil.copy2(ROT, f"/root/mia-backup/{ROT.replace('/', '_')}.{STAMP}")
        with open(ROT, "w") as fh:
            fh.write(rot_text)
        os.chmod(ROT, 0o644)
    chk = subprocess.run(["logrotate", "-d", "/etc/logrotate.conf"], capture_output=True, text=True)
    errs = [l for l in (chk.stdout + chk.stderr).splitlines() if l.startswith("error:") and ("cron-jobs" in l or any(p in l for p in rotate))]
    result["logrotateErrors"] = errs
    if errs and os.path.exists(ROT) and result["rotation"]["rewrite"]:
        # never leave logrotate broken: put the old file back
        if cur_rot:
            open(ROT, "w").write(cur_rot)
        else:
            os.remove(ROT)
        result["rolledBack"] = True
print(json.dumps(result, ensure_ascii=False))
