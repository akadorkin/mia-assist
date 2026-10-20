import fs from 'node:fs';
import path from 'node:path';
import { Config } from '../config.js';
import { redact } from './output.js';

export interface JournalEntry {
    at: string;
    tool: string;
    host: string;
    action: string;
    ok: boolean;
    /** Short outcome / error. */
    result?: string;
    ms?: number;
    planHash?: string;
}

export interface SnapshotMeta {
    host: string;
    file: string;
    takenAt: string;
    reason: string;
}

const KEEP_SNAPSHOTS = 200;

/**
 * Everything the server remembers between runs, under MIA_STATE_DIR:
 *   journal.jsonl            every action it ran on a host (who/what/when/outcome)
 *   snapshots/<host>/*.json  state of a host at a point in time, for drift / change history
 *   out/                     oversized tool results
 */
export class StateStore {
    readonly journalFile: string;
    readonly snapshotDir: string;

    constructor(config: Config) {
        this.journalFile = path.join(config.stateDir, 'journal.jsonl');
        this.snapshotDir = path.join(config.stateDir, 'snapshots');
    }

    log(entry: Omit<JournalEntry, 'at'>) {
        fs.mkdirSync(path.dirname(this.journalFile), { recursive: true, mode: 0o700 });
        const line: JournalEntry = redact({ at: new Date().toISOString(), ...entry });
        fs.appendFileSync(this.journalFile, JSON.stringify(line) + '\n', { mode: 0o600 });
    }

    journal(opts: { limit?: number; host?: string; contains?: string; since?: string } = {}): JournalEntry[] {
        if (!fs.existsSync(this.journalFile)) return [];
        const lines = fs.readFileSync(this.journalFile, 'utf8').trim().split('\n').filter(Boolean);
        let list = lines.map((l) => JSON.parse(l) as JournalEntry);
        if (opts.host) list = list.filter((e) => e.host === opts.host);
        if (opts.since) list = list.filter((e) => e.at >= opts.since!);
        if (opts.contains) list = list.filter((e) => JSON.stringify(e).includes(opts.contains!));
        return list.slice(-(opts.limit ?? 50)).reverse();
    }

    saveSnapshot(host: string, reason: string, data: unknown): SnapshotMeta {
        const dir = path.join(this.snapshotDir, host);
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        const takenAt = new Date().toISOString();
        const file = path.join(dir, `${takenAt.replace(/[:.]/g, '-')}.json`);
        fs.writeFileSync(file, JSON.stringify({ host, takenAt, reason, state: redact(data) }, null, 1), { mode: 0o600 });
        const all = this.listSnapshots(host);
        for (const old of all.slice(KEEP_SNAPSHOTS)) fs.rmSync(old.file, { force: true });
        return { host, file, takenAt, reason };
    }

    /** Newest first. */
    listSnapshots(host: string): SnapshotMeta[] {
        const dir = path.join(this.snapshotDir, host);
        if (!fs.existsSync(dir)) return [];
        return fs
            .readdirSync(dir)
            .filter((f) => f.endsWith('.json'))
            .sort()
            .reverse()
            .map((f) => {
                const file = path.join(dir, f);
                const head = JSON.parse(fs.readFileSync(file, 'utf8')) as { takenAt: string; reason: string };
                return { host, file, takenAt: head.takenAt, reason: head.reason };
            });
    }

    readSnapshot(file: string): { host: string; takenAt: string; reason: string; state: Record<string, unknown> } {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    }

    snapshotHosts(): string[] {
        if (!fs.existsSync(this.snapshotDir)) return [];
        return fs.readdirSync(this.snapshotDir).filter((d) => fs.statSync(path.join(this.snapshotDir, d)).isDirectory());
    }

    /** Where detached remote jobs (bootstrap, upgrades) are tracked locally. */
    jobsFile(): string {
        return path.join(path.dirname(this.journalFile), 'jobs.json');
    }

    readJobs(): Record<string, Job> {
        const f = this.jobsFile();
        return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : {};
    }

    saveJob(job: Job) {
        const jobs = this.readJobs();
        jobs[job.id] = job;
        fs.mkdirSync(path.dirname(this.jobsFile()), { recursive: true, mode: 0o700 });
        fs.writeFileSync(this.jobsFile(), JSON.stringify(jobs, null, 1), { mode: 0o600 });
    }
}

/** A long remote command started detached (nohup), polled with job_status. */
export interface Job {
    id: string;
    host: string;
    kind: string;
    startedAt: string;
    /** Remote log file. */
    log: string;
    /** Remote file holding the exit code once done. */
    rcFile: string;
    /** How to reach the host for polling, if not its inventory address. */
    via?: { address: string; user?: string; port?: number; identityFile?: string };
    note?: string;
}
