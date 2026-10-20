import crypto from 'node:crypto';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AppHandle, HttpCall, appGet, appOf, httpEnv, locateFolder } from '../core/apps.js';
import { Ctx } from '../core/ctx.js';
import { HostStep, applyParams, runSteps } from '../core/plan.js';
import { run, writeTools } from './helpers.js';

const hostParam = z.string().describe('host name from the inventory that has apps.jellyfin / apps.tdarr');

// ---------------------------------------------------------------- batched HTTP for write steps

/**
 * Several API calls in one host step, run in order, stopping at the first non-2xx.
 * Prints "HTTP <n> <status> <label>" per call plus a short body.
 */
export function httpBatch(a: AppHandle, calls: Array<HttpCall & { label: string }>): { script: string; env: Record<string, string> } {
    const env: Record<string, string> = { AUTH_HEADER: a.authHeader };
    const lines = [
        'command -v curl >/dev/null || { echo "curl is not installed on this host"; exit 3; }',
        `cfg() { if [ -n "$AUTH_HEADER" ]; then printf 'header = "%s"\\n' "$AUTH_HEADER"; fi; }`,
        'out=$(mktemp); trap \'rm -f "$out"\' EXIT',
        'req() {',
        '  if [ -n "$3" ]; then printf \'%s\' "$3" | curl -sS -m "$4" -X "$1" -K <(cfg) -H \'Content-Type: application/json\' --data-binary @- -o "$out" -w \'%{http_code}\' "$2"',
        '  else curl -sS -m "$4" -X "$1" -K <(cfg) -o "$out" -w \'%{http_code}\' "$2"; fi',
        '}',
    ];
    calls.forEach((c, i) => {
        const e = httpEnv(a, c);
        env[`M_${i}`] = e.METHOD;
        env[`U_${i}`] = e.URL;
        env[`B_${i}`] = e.BODY;
        env[`T_${i}`] = e.TIMEOUT;
        env[`L_${i}`] = c.label;
        lines.push(
            `code=$(req "$M_${i}" "$U_${i}" "$B_${i}" "$T_${i}"); echo "HTTP ${i + 1} \${code:-000} $L_${i}"; head -c 400 "$out"; echo`,
            `case "$code" in 2*) ;; *) echo "stopped at call ${i + 1}"; exit 4 ;; esac`,
        );
    });
    return { script: lines.join('\n'), env };
}

const showCall = (c: HttpCall & { label: string }) => ({ call: `${c.method} ${c.path}`, ...(c.body !== undefined ? { body: c.body } : {}), what: c.label });

// ---------------------------------------------------------------- Jellyfin

interface JfFolder {
    Name: string;
    Locations: string[];
    CollectionType?: string;
    ItemId: string;
    RefreshStatus?: string;
    RefreshProgress?: number;
    LibraryOptions?: Record<string, unknown>;
}

interface JfTask {
    Name: string;
    Key: string;
    Id: string;
    State: string;
    Category?: string;
    IsHidden?: boolean;
    CurrentProgressPercentage?: number;
    LastExecutionResult?: { Status: string; EndTimeUtc?: string; ErrorMessage?: string };
}

const JF_TYPES = ['movies', 'tvshows', 'music', 'musicvideos', 'homevideos', 'boxsets', 'books', 'mixed'] as const;

async function jfFolders(ctx: Ctx, a: AppHandle): Promise<JfFolder[]> {
    return appGet<JfFolder[]>(ctx, a, { method: 'GET', path: '/Library/VirtualFolders' });
}

function findLibrary<T extends { Name?: string; name?: string }>(list: T[], name: string, what: string): T {
    const n = (x: T) => (x.Name ?? x.name ?? '').toLowerCase();
    const hit = list.find((x) => n(x) === name.toLowerCase());
    if (!hit) throw new Error(`no ${what} library "${name}"; there are: ${list.map((x) => x.Name ?? x.name).join(', ') || 'none'}`);
    return hit;
}

// ---------------------------------------------------------------- Tdarr

interface TdarrLibrary {
    _id: string;
    name: string;
    folder: string;
    cache?: string;
    output?: string;
    priority?: number;
    [k: string]: unknown;
}

const cruddb = (collection: string, mode: string, extra: Record<string, unknown> = {}) => ({ data: { collection, mode, ...extra }, timeout: 20000 });

async function tdarrLibraries(ctx: Ctx, a: AppHandle): Promise<TdarrLibrary[]> {
    const r = await appGet<TdarrLibrary[]>(ctx, a, { method: 'POST', path: '/api/v2/cruddb', body: cruddb('LibrarySettingsJSONDB', 'getAll') });
    return Array.isArray(r) ? r : [];
}

/** Tdarr-style short id. */
export function tdarrId(): string {
    const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from(crypto.randomBytes(9), (b) => abc[b % abc.length]).join('');
}

/**
 * A new library settings object cloned from an existing one: same flow / plugin stack,
 * transcode and health-check settings; new id, name and folder; counters reset.
 */
export function cloneTdarrLibrary(
    template: TdarrLibrary,
    opts: { id: string; name: string; folder: string; cache?: string; output?: string; priority?: number },
): { obj: TdarrLibrary; reset: string[] } {
    const obj = JSON.parse(JSON.stringify(template)) as TdarrLibrary;
    const reset: string[] = [];
    for (const [k, v] of Object.entries(obj)) {
        if (typeof v === 'number' && /count|sizediff|total|saved/i.test(k) && !/thread|limit|priority|worker/i.test(k) && v !== 0) {
            obj[k] = 0;
            reset.push(k);
        }
    }
    obj._id = opts.id;
    obj.name = opts.name;
    obj.folder = opts.folder;
    if (opts.cache) obj.cache = opts.cache;
    if (opts.output) obj.output = opts.output;
    if (opts.priority !== undefined && typeof template.priority === 'number') obj.priority = opts.priority;
    return { obj, reset };
}

// ---------------------------------------------------------------- tools

export function registerMediaTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'jellyfin_status',
        'Jellyfin on a host: version and pending restart, libraries (type, folders — with their host paths — and scan state), who is watching what right now (direct play vs transcode), item counts, scheduled tasks that failed last time or are running.',
        { host: hostParam },
        ({ host }) =>
            run(async () => {
                const a = appOf(ctx.inventory().get(host), 'jellyfin');
                const [info, folders, sessions, counts, tasks] = await Promise.all([
                    appGet<Record<string, unknown>>(ctx, a, { method: 'GET', path: '/System/Info' }),
                    jfFolders(ctx, a),
                    appGet<Array<Record<string, any>>>(ctx, a, { method: 'GET', path: '/Sessions?activeWithinSeconds=900' }),
                    appGet<Record<string, number>>(ctx, a, { method: 'GET', path: '/Items/Counts' }),
                    appGet<JfTask[]>(ctx, a, { method: 'GET', path: '/ScheduledTasks?isHidden=false' }),
                ]);
                const playing = sessions.filter((s) => s.NowPlayingItem);
                return {
                    host,
                    server: `${info.ServerName} ${info.Version}${info.HasPendingRestart ? ' (restart pending)' : ''}`,
                    libraries: folders.map((f) => ({
                        name: f.Name,
                        type: f.CollectionType ?? 'mixed',
                        folders: f.Locations,
                        ...(f.RefreshStatus && f.RefreshStatus !== 'Idle' ? { scan: `${f.RefreshStatus} ${Math.round(f.RefreshProgress ?? 0)}%` } : {}),
                    })),
                    counts: Object.fromEntries(Object.entries(counts).filter(([, v]) => v)),
                    watching: playing.map((s) => ({
                        user: s.UserName,
                        client: `${s.Client} / ${s.DeviceName}`,
                        item: [s.NowPlayingItem.SeriesName, s.NowPlayingItem.Name].filter(Boolean).join(' — '),
                        mode: s.PlayState?.PlayMethod ?? '?',
                        ...(s.TranscodingInfo ? { transcode: (s.TranscodingInfo.TranscodeReasons ?? []).join(',') || 'yes' } : {}),
                        paused: s.PlayState?.IsPaused || undefined,
                    })),
                    sessionsActive: sessions.length,
                    tasksRunning: tasks.filter((t) => t.State !== 'Idle').map((t) => `${t.Name} ${Math.round(t.CurrentProgressPercentage ?? 0)}%`),
                    tasksFailed: tasks
                        .filter((t) => t.LastExecutionResult && t.LastExecutionResult.Status !== 'Completed')
                        .map((t) => `${t.Name}: ${t.LastExecutionResult!.Status}${t.LastExecutionResult!.ErrorMessage ? ` — ${t.LastExecutionResult!.ErrorMessage}` : ''} (${t.LastExecutionResult!.EndTimeUtc?.slice(0, 16)})`),
                    tasks: tasks.map((t) => t.Name),
                };
            }),
    );

    server.tool(
        'tdarr_status',
        'Tdarr on a host: server version/uptime, nodes (paused, workers), libraries (folder, cache, output, watching, processing), global pause, overall statistics.',
        { host: hostParam },
        ({ host }) =>
            run(async () => {
                const a = appOf(ctx.inventory().get(host), 'tdarr');
                const [status, nodes, libs, global, stats] = await Promise.all([
                    appGet<Record<string, unknown>>(ctx, a, { method: 'GET', path: '/api/v2/status' }),
                    appGet<Record<string, Record<string, any>>>(ctx, a, { method: 'GET', path: '/api/v2/get-nodes' }),
                    tdarrLibraries(ctx, a),
                    appGet<Record<string, unknown>>(ctx, a, { method: 'POST', path: '/api/v2/cruddb', body: cruddb('SettingsGlobalJSONDB', 'getById', { docID: 'globalsettings' }) }).catch(() => ({})),
                    appGet<Record<string, unknown>>(ctx, a, { method: 'POST', path: '/api/v2/cruddb', body: cruddb('StatisticsJSONDB', 'getById', { docID: 'statistics' }) }).catch(() => ({})),
                ]);
                return {
                    host,
                    server: status,
                    pauseAllNodes: (global as Record<string, unknown>).pauseAllNodes,
                    nodes: Object.values(nodes ?? {}).map((n) => ({
                        name: n.nodeName ?? n._id,
                        paused: n.nodePaused,
                        workers: n.workers ? Object.keys(n.workers).length : 0,
                        limits: n.workerLimits,
                    })),
                    libraries: libs.map((l) => ({
                        name: l.name,
                        id: l._id,
                        folder: l.folder,
                        cache: l.cache,
                        output: l.output,
                        watching: l.folderWatching,
                        processing: l.processLibrary,
                        scanOnStart: l.scanOnStart,
                    })),
                    stats: Object.fromEntries(Object.entries(stats as Record<string, unknown>).filter(([k, v]) => typeof v === 'number' && /total|size|count/i.test(k))),
                };
            }),
    );

    writeTools(() => {
        if (ctx.config.readonly) return;

        server.tool(
            'jellyfin_library_add_path',
            'Add a folder to an existing Jellyfin library. The folder may be given as a host path (translated through the Jellyfin container mounts) or as the path inside the container; it must exist on both sides. Optionally scans the library afterwards.',
            {
                host: hostParam,
                library: z.string().describe('library name as in jellyfin_status'),
                path: z.string().describe('folder, absolute (host or container path)'),
                scan: z.boolean().default(true),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'jellyfin_library_add_path', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const a = appOf(h, 'jellyfin');
                        const lib = findLibrary(await jfFolders(ctx, a), args.library, 'Jellyfin');
                        const loc = await locateFolder(ctx, a, args.path);
                        const calls = [{ label: `add ${loc.appPath} to "${lib.Name}"`, method: 'POST' as const, path: `/Library/VirtualFolders/Paths?refreshLibrary=${args.scan}`, body: { Name: lib.Name, PathInfo: { Path: loc.appPath } } }];
                        const step: HostStep = {
                            host: h,
                            action: `jellyfin: add ${loc.appPath} to library "${lib.Name}"${args.scan ? ' + scan' : ''}`,
                            ...httpBatch(a, calls),
                            preview: { library: `${lib.Name} (${lib.CollectionType ?? 'mixed'})`, folders: lib.Locations, path: loc.notes, content: loc.stats, requests: calls.map(showCall) },
                            fingerprint: [lib.Locations, loc.appPath],
                            blockers: loc.problems,
                            timeoutMs: 120_000,
                        };
                        if (lib.Locations.includes(loc.appPath)) step.noop = `${loc.appPath} is already in "${lib.Name}"`;
                        return [step];
                    }),
                ),
        );

        server.tool(
            'jellyfin_library_create',
            'Create a Jellyfin library with folders. Library options (metadata language, savers, fetchers …) can be copied from an existing library of your choice; otherwise Jellyfin defaults apply.',
            {
                host: hostParam,
                name: z.string().regex(/^\S(?:.*\S)?$/, 'no leading/trailing spaces'),
                type: z.enum(JF_TYPES),
                paths: z.array(z.string()).min(1).describe('folders (host or container paths)'),
                optionsFrom: z.string().optional().describe('existing library whose LibraryOptions to copy'),
                scan: z.boolean().default(true),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'jellyfin_library_create', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const a = appOf(h, 'jellyfin');
                        const folders = await jfFolders(ctx, a);
                        const locs = await Promise.all(args.paths.map((p) => locateFolder(ctx, a, p)));
                        const blockers = locs.flatMap((l) => l.problems);
                        if (folders.some((f) => f.Name.toLowerCase() === args.name.toLowerCase())) blockers.push(`a library "${args.name}" already exists: use jellyfin_library_add_path`);
                        let options: Record<string, unknown> = {};
                        if (args.optionsFrom) {
                            const t = findLibrary(folders, args.optionsFrom, 'Jellyfin');
                            options = { ...(t.LibraryOptions ?? {}) };
                            delete options.PathInfos;
                        }
                        const paths = locs.map((l) => l.appPath);
                        const qs = new URLSearchParams({ name: args.name, collectionType: args.type, paths: paths.join(','), refreshLibrary: String(args.scan) });
                        const calls = [{ label: `create "${args.name}"`, method: 'POST' as const, path: `/Library/VirtualFolders?${qs}`, body: { LibraryOptions: options } }];
                        return [
                            {
                                host: h,
                                action: `jellyfin: create ${args.type} library "${args.name}" with ${paths.join(', ')}${args.scan ? ' + scan' : ''}`,
                                ...httpBatch(a, calls),
                                preview: {
                                    existing: folders.map((f) => f.Name),
                                    paths: locs.map((l) => ({ path: l.appPath, notes: l.notes, content: l.stats })),
                                    optionsFrom: args.optionsFrom ?? 'Jellyfin defaults',
                                    requests: calls.map((c) => ({ ...showCall(c), body: args.optionsFrom ? `{LibraryOptions: <${Object.keys(options).length} options from "${args.optionsFrom}">}` : c.body })),
                                },
                                fingerprint: [folders.map((f) => f.Name), paths],
                                blockers,
                                timeoutMs: 120_000,
                            },
                        ];
                    }),
                ),
        );

        server.tool(
            'jellyfin_scan',
            'Scan Jellyfin for new/changed files: one library (metadata/images for new items only) or all libraries.',
            { host: hostParam, library: z.string().optional().describe('default: all libraries'), ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'jellyfin_scan', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const a = appOf(h, 'jellyfin');
                        const folders = await jfFolders(ctx, a);
                        const lib = args.library ? findLibrary(folders, args.library, 'Jellyfin') : undefined;
                        const calls = [
                            lib
                                ? { label: `scan "${lib.Name}"`, method: 'POST' as const, path: `/Items/${lib.ItemId}/Refresh?metadataRefreshMode=Default&imageRefreshMode=Default&replaceAllMetadata=false&replaceAllImages=false` }
                                : { label: 'scan all libraries', method: 'POST' as const, path: '/Library/Refresh' },
                        ];
                        const busy = folders.filter((f) => f.RefreshStatus && f.RefreshStatus !== 'Idle').map((f) => f.Name);
                        return [
                            {
                                host: h,
                                action: `jellyfin: ${calls[0].label}`,
                                ...httpBatch(a, calls),
                                preview: { requests: calls.map(showCall), ...(busy.length ? { alreadyScanning: busy } : {}) },
                                timeoutMs: 60_000,
                            },
                        ];
                    }),
                ),
        );

        server.tool(
            'jellyfin_task_run',
            'Start a Jellyfin scheduled task by name or key (e.g. "Scan Media Library", "Extract Chapter Images", "Clean Cache", RefreshLibrary).',
            { host: hostParam, task: z.string(), ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'jellyfin_task_run', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const a = appOf(h, 'jellyfin');
                        const tasks = await appGet<JfTask[]>(ctx, a, { method: 'GET', path: '/ScheduledTasks' });
                        const t = tasks.find((x) => x.Key.toLowerCase() === args.task.toLowerCase() || x.Name.toLowerCase() === args.task.toLowerCase());
                        if (!t) throw new Error(`no task "${args.task}"; tasks: ${tasks.filter((x) => !x.IsHidden).map((x) => `${x.Name} (${x.Key})`).join(', ')}`);
                        const calls = [{ label: `start "${t.Name}"`, method: 'POST' as const, path: `/ScheduledTasks/Running/${t.Id}` }];
                        const step: HostStep = {
                            host: h,
                            action: `jellyfin: start task "${t.Name}"`,
                            ...httpBatch(a, calls),
                            preview: { task: `${t.Name} (${t.Category})`, state: t.State, last: t.LastExecutionResult ? `${t.LastExecutionResult.Status} ${t.LastExecutionResult.EndTimeUtc?.slice(0, 16)}` : 'never', requests: calls.map(showCall) },
                            timeoutMs: 60_000,
                        };
                        if (t.State === 'Running') step.noop = 'already running';
                        return [step];
                    }),
                ),
        );

        server.tool(
            'tdarr_library_add',
            'Add folders to Tdarr: one new library per folder, cloned from an existing library (same flow/plugin stack, transcode/health-check settings, cache and output unless given), with counters reset. Folders may be host paths (translated through the Tdarr container mounts). The dry run shows every library object that will be inserted. Optionally starts a "find new" scan of each.',
            {
                host: hostParam,
                folders: z.array(z.string()).min(1).describe('absolute folders, host or container paths'),
                template: z.string().describe('existing Tdarr library to copy settings from'),
                names: z.array(z.string()).optional().describe('library names, same order as folders (default: the folder name)'),
                cache: z.string().optional().describe('transcode cache folder (default: the template\'s)'),
                output: z.string().optional().describe('output folder when the template converts folder-to-folder'),
                scan: z.boolean().default(true).describe('scanFindNew each new library afterwards'),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'tdarr_library_add', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const a = appOf(h, 'tdarr');
                        const libs = await tdarrLibraries(ctx, a);
                        const template = findLibrary(libs, args.template, 'Tdarr');
                        if (args.names && args.names.length !== args.folders.length) throw new Error('names must have one entry per folder');
                        const locs = await Promise.all(args.folders.map((f) => locateFolder(ctx, a, f)));
                        const cacheLoc = args.cache ? await locateFolder(ctx, a, args.cache) : undefined;
                        const blockers = [...locs.flatMap((l) => l.problems), ...(cacheLoc?.problems ?? [])];
                        const warnings: string[] = [];
                        const maxPrio = Math.max(0, ...libs.map((l) => (typeof l.priority === 'number' ? l.priority : 0)));
                        const calls: Array<HttpCall & { label: string }> = [];
                        const objects: unknown[] = [];
                        locs.forEach((loc, i) => {
                            const name = args.names?.[i] ?? path.posix.basename(loc.appPath.replace(/\/+$/, ''));
                            if (libs.some((l) => l.folder.replace(/\/+$/, '') === loc.appPath.replace(/\/+$/, ''))) blockers.push(`${loc.appPath} is already the folder of library "${libs.find((l) => l.folder.replace(/\/+$/, '') === loc.appPath.replace(/\/+$/, ''))!.name}"`);
                            const nested = libs.find((l) => loc.appPath.startsWith(l.folder.replace(/\/+$/, '') + '/') || l.folder.startsWith(loc.appPath.replace(/\/+$/, '') + '/'));
                            if (nested) warnings.push(`${loc.appPath} overlaps library "${nested.name}" (${nested.folder}): files would be processed twice`);
                            if (libs.some((l) => l.name.toLowerCase() === name.toLowerCase())) blockers.push(`a library named "${name}" exists: pass names`);
                            const id = tdarrId();
                            const { obj, reset } = cloneTdarrLibrary(template, { id, name, folder: loc.appPath, cache: cacheLoc?.appPath, output: args.output, priority: maxPrio + 1 + i });
                            objects.push({ ...obj, ...(reset.length ? { '(reset)': reset } : {}) });
                            calls.push({ label: `insert library "${name}" (${loc.appPath})`, method: 'POST', path: '/api/v2/cruddb', body: cruddb('LibrarySettingsJSONDB', 'insert', { docID: id, obj }) });
                            if (args.scan) calls.push({ label: `scan "${name}"`, method: 'POST', path: '/api/v2/scan-files', body: { data: { scanConfig: { dbID: id, arrayOrPath: loc.appPath, mode: 'scanFindNew' } } }, timeoutSec: 60 });
                        });
                        if (template.folderToFolderConversion && !args.output) warnings.push(`the template writes to output folder ${template.output}: the new libraries will write there too unless you pass output`);
                        if (a.spec.container) warnings.push('Tdarr nodes running in other containers/machines need the same folders mapped at the same paths');
                        return [
                            {
                                host: h,
                                action: `tdarr: add ${locs.length} librar${locs.length > 1 ? 'ies' : 'y'} from template "${template.name}": ${locs.map((l) => l.appPath).join(', ')}${args.scan ? ' + scan' : ''}`,
                                ...httpBatch(a, calls),
                                preview: {
                                    template: { name: template.name, folder: template.folder, cache: template.cache, output: template.output },
                                    folders: locs.map((l) => ({ path: l.appPath, notes: l.notes, content: l.stats })),
                                    libraries: objects,
                                    requests: calls.map((c) => ({ call: `${c.method} ${c.path}`, what: c.label })),
                                },
                                // ids are random: the fingerprint uses what the plan depends on, not the ids
                                fingerprint: [libs.map((l) => [l.name, l.folder]), locs.map((l) => l.appPath), template._id],
                                warnings,
                                blockers,
                                timeoutMs: 300_000,
                            },
                        ];
                    }),
                ),
        );

        server.tool(
            'tdarr_scan',
            'Scan a Tdarr library: scanFindNew (only new files, default) or scanFresh (re-scan everything).',
            { host: hostParam, library: z.string(), mode: z.enum(['scanFindNew', 'scanFresh']).default('scanFindNew'), ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'tdarr_scan', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const a = appOf(h, 'tdarr');
                        const lib = findLibrary(await tdarrLibraries(ctx, a), args.library, 'Tdarr');
                        const calls = [{ label: `${args.mode} "${lib.name}"`, method: 'POST' as const, path: '/api/v2/scan-files', body: { data: { scanConfig: { dbID: lib._id, arrayOrPath: lib.folder, mode: args.mode } } }, timeoutSec: 60 }];
                        return [{ host: h, action: `tdarr: ${calls[0].label}`, ...httpBatch(a, calls), preview: { folder: lib.folder, requests: calls.map(showCall) }, timeoutMs: 120_000 }];
                    }),
                ),
        );

        server.tool(
            'tdarr_pause',
            'Pause or resume all Tdarr nodes (global setting), e.g. while the server is busy streaming.',
            { host: hostParam, paused: z.boolean(), ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'tdarr_pause', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        const a = appOf(h, 'tdarr');
                        const g = await appGet<Record<string, unknown>>(ctx, a, { method: 'POST', path: '/api/v2/cruddb', body: cruddb('SettingsGlobalJSONDB', 'getById', { docID: 'globalsettings' }) });
                        const calls = [{ label: args.paused ? 'pause all nodes' : 'resume all nodes', method: 'POST' as const, path: '/api/v2/cruddb', body: cruddb('SettingsGlobalJSONDB', 'update', { docID: 'globalsettings', obj: { pauseAllNodes: args.paused } }) }];
                        const step: HostStep = { host: h, action: `tdarr: ${calls[0].label}`, ...httpBatch(a, calls), preview: { pauseAllNodes: g.pauseAllNodes, requests: calls.map(showCall) }, fingerprint: g.pauseAllNodes, timeoutMs: 60_000 };
                        if (g.pauseAllNodes === args.paused) step.noop = `already ${args.paused ? 'paused' : 'running'}`;
                        return [step];
                    }),
                ),
        );
    });
}
