import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { stringify } from 'yaml';
import { loadConfig } from '../src/config.js';
import { parseHttp, resolveKey, toContainerPath, toHostPath } from '../src/core/apps.js';
import { createServer } from '../src/server.js';
import { registry } from '../src/tools/helpers.js';
import { cloneTdarrLibrary } from '../src/tools/media.js';

// ---------------------------------------------------------------- pure helpers

test('host ↔ container paths through bind mounts (longest match wins)', () => {
    const mounts = [
        { src: '/mnt/data', dst: '/data', rw: true },
        { src: '/mnt/data/media', dst: '/media', rw: false },
        { src: '/srv/jellyfin/config', dst: '/config', rw: true },
    ];
    assert.deepEqual(toContainerPath(mounts, '/mnt/data/media/clips/90s/')?.path, '/media/clips/90s');
    assert.equal(toContainerPath(mounts, '/mnt/data/media/clips')?.mount.rw, false);
    assert.equal(toContainerPath(mounts, '/mnt/data/downloads')?.path, '/data/downloads');
    assert.equal(toContainerPath(mounts, '/mnt/database'), undefined, 'prefix must end at a path boundary');
    assert.equal(toContainerPath(mounts, '/mnt/data')?.path, '/data');
    assert.equal(toHostPath(mounts, '/media/movies'), '/mnt/data/media/movies');
    assert.equal(toHostPath(mounts, '/elsewhere'), undefined);
});

test('curl output parsing', () => {
    assert.deepEqual(parseHttp('{"a":1}\n200'), { status: 200, body: { a: 1 }, raw: '{"a":1}' });
    assert.deepEqual(parseHttp('\n204\n'), { status: 204, body: '', raw: '' });
    assert.equal(parseHttp('curl: (7) Failed to connect\n000').status, 0);
});

test('API keys: env: indirection, unsafe characters rejected', () => {
    process.env.MIA_TEST_KEY = 'abc123';
    assert.equal(resolveKey('env:MIA_TEST_KEY', 'x'), 'abc123');
    assert.equal(resolveKey('literal', 'x'), 'literal');
    assert.equal(resolveKey(undefined, 'x'), '');
    assert.throws(() => resolveKey('env:MIA_NOPE_KEY', 'x'), /not set/);
    assert.throws(() => resolveKey('a"b', 'x'), /quotes/);
});

test('tdarr library clone: new id/name/folder, same flow, counters reset', () => {
    const template = {
        _id: 'tmpl1',
        name: 'Movies',
        folder: '/media/movies',
        cache: '/temp',
        output: '/out',
        priority: 2,
        flowId: 'flow-abc',
        pluginIDs: [{ _id: 'p1', checked: true }],
        totalTranscodeCount: 120,
        totalHealthCheckCount: 40,
        sizeDiff: 55.5,
        scannerThreadCount: 2,
        processLibrary: true,
    };
    const { obj, reset } = cloneTdarrLibrary(template, { id: 'new1', name: 'Clips', folder: '/media/clips', priority: 5 });
    assert.equal(obj._id, 'new1');
    assert.equal(obj.name, 'Clips');
    assert.equal(obj.folder, '/media/clips');
    assert.equal(obj.cache, '/temp');
    assert.equal(obj.flowId, 'flow-abc');
    assert.deepEqual(obj.pluginIDs, template.pluginIDs);
    assert.equal(obj.priority, 5);
    assert.equal(obj.scannerThreadCount, 2, 'thread settings are not counters');
    assert.deepEqual(reset.sort(), ['sizeDiff', 'totalHealthCheckCount', 'totalTranscodeCount']);
    assert.equal(template.totalTranscodeCount, 120, 'template untouched');
});

// ---------------------------------------------------------------- tools against API mocks, through the real curl scripts

type Req = { method: string; url: string; headers: http.IncomingHttpHeaders; body: string };
const seen: Req[] = [];
let server: http.Server;
let base = '';
let dir = '';

const jfFolders = () => [
    { Name: 'Movies', Locations: ['/media/movies'], CollectionType: 'movies', ItemId: 'aaa111', RefreshStatus: 'Idle', LibraryOptions: { PreferredMetadataLanguage: 'ru', PathInfos: [{ Path: '/media/movies' }] } },
    { Name: 'Clips', Locations: ['/media/clips'], CollectionType: 'musicvideos', ItemId: 'bbb222', RefreshStatus: 'Idle' },
];
const tdarrLibs = [{ _id: 'L1', name: 'Movies', folder: '/media/movies', cache: '/temp', output: '', priority: 1, flowId: 'f1', totalTranscodeCount: 9, folderWatching: true }];

before(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-media-'));
    fs.mkdirSync(path.join(dir, 'clips90'));
    fs.writeFileSync(path.join(dir, 'clips90', 'a.mkv'), 'x');
    server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (d) => (body += d));
        req.on('end', () => {
            seen.push({ method: req.method!, url: req.url!, headers: req.headers, body });
            const json = (code: number, v?: unknown) => {
                res.writeHead(code, { 'content-type': 'application/json' });
                res.end(v === undefined ? '' : JSON.stringify(v));
            };
            const u = req.url!;
            // Jellyfin
            if (u.startsWith('/jf/')) {
                if (req.headers['x-emby-token'] !== 'jfkey') return json(401, { message: 'Unauthorized' });
                if (u === '/jf/Library/VirtualFolders') return json(200, jfFolders());
                if (u.startsWith('/jf/Library/VirtualFolders/Paths')) return json(204);
                if (u.startsWith('/jf/Library/VirtualFolders?')) return json(204);
                return json(404);
            }
            // Tdarr
            if (u.startsWith('/td/')) {
                if (req.headers['x-api-key'] !== 'tdkey') return json(401);
                const b = body ? JSON.parse(body) : {};
                if (u === '/td/api/v2/cruddb' && b.data?.mode === 'getAll') return json(200, tdarrLibs);
                if (u === '/td/api/v2/cruddb' && b.data?.mode === 'insert') return json(200, 'OK');
                if (u === '/td/api/v2/scan-files') return b.data?.scanConfig?.dbID === 'FAIL' ? json(500, 'nope') : json(200, 'OK');
                return json(404);
            }
            json(404);
        });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    process.env.MIA_T_JF = 'jfkey';
    fs.writeFileSync(
        path.join(dir, 'fleet.yaml'),
        stringify({
            hosts: {
                home: {
                    transport: 'local',
                    apps: { jellyfin: { url: `${base}/jf`, apiKey: 'env:MIA_T_JF' }, tdarr: { url: `${base}/td`, apiKey: 'tdkey' } },
                },
            },
        }),
    );
    createServer(loadConfig({ MIA_INVENTORY: path.join(dir, 'fleet.yaml'), MIA_STATE_DIR: path.join(dir, 'state') }));
});

after(() => server.close());

async function call(tool: string, args: Record<string, unknown>) {
    const t = registry.get(tool)!;
    const res = await t.handler(args);
    const text = res.content[0].text;
    if (res.isError) throw new Error(text);
    return JSON.parse(text);
}

test('jellyfin_library_add_path: dry run sends nothing, apply posts exactly the planned request', async () => {
    const folder = path.join(dir, 'clips90');
    seen.length = 0;
    const dry = await call('jellyfin_library_add_path', { host: 'home', library: 'clips', path: folder, scan: true, apply: false });
    assert.equal(dry.mode, 'dry-run');
    assert.deepEqual(dry.plan[0].now.requests[0], { call: `POST /Library/VirtualFolders/Paths?refreshLibrary=true`, body: { Name: 'Clips', PathInfo: { Path: folder } }, what: `add ${folder} to "Clips"` });
    assert.match(dry.plan[0].now.content, /1 files/);
    assert.ok(seen.every((r) => r.method === 'GET'), 'dry run only reads');

    seen.length = 0;
    const done = await call('jellyfin_library_add_path', { host: 'home', library: 'clips', path: folder, scan: true, apply: true, planHash: dry.planHash });
    assert.equal(done.mode, 'applied', JSON.stringify(done));
    const post = seen.find((r) => r.method === 'POST')!;
    assert.equal(post.url, '/jf/Library/VirtualFolders/Paths?refreshLibrary=true');
    assert.deepEqual(JSON.parse(post.body), { Name: 'Clips', PathInfo: { Path: folder } });
    assert.equal(post.headers['x-emby-token'], 'jfkey');
});

test('jellyfin_library_add_path: missing folder and duplicates are caught before anything is sent', async () => {
    const missing = await call('jellyfin_library_add_path', { host: 'home', library: 'Clips', path: path.join(dir, 'nope'), scan: false, apply: false });
    assert.match(missing.blocked[0], /does not exist/);
    const dup = await call('jellyfin_library_add_path', { host: 'home', library: 'Movies', path: '/media/movies', scan: false, apply: false });
    assert.match(dup.plan[0].skip ?? dup.blocked?.[0], /already in "Movies"|does not exist/);
});

test('jellyfin_library_create copies options from another library without its paths', async () => {
    const folder = path.join(dir, 'clips90');
    const dry = await call('jellyfin_library_create', { host: 'home', name: 'Клипы 90-х', type: 'musicvideos', paths: [folder], optionsFrom: 'Movies', scan: false, apply: false });
    seen.length = 0;
    const done = await call('jellyfin_library_create', { host: 'home', name: 'Клипы 90-х', type: 'musicvideos', paths: [folder], optionsFrom: 'Movies', scan: false, apply: true, planHash: dry.planHash });
    assert.equal(done.mode, 'applied', JSON.stringify(done));
    const post = seen.find((r) => r.method === 'POST')!;
    const u = new URL(post.url, 'http://x');
    assert.equal(u.pathname, '/jf/Library/VirtualFolders');
    assert.equal(u.searchParams.get('name'), 'Клипы 90-х');
    assert.equal(u.searchParams.get('collectionType'), 'musicvideos');
    assert.equal(u.searchParams.get('paths'), folder);
    assert.deepEqual(JSON.parse(post.body), { LibraryOptions: { PreferredMetadataLanguage: 'ru' } });
});

test('tdarr_library_add: inserts a clone per folder, then scans it; wrong planHash sends nothing', async () => {
    const folder = path.join(dir, 'clips90');
    const dry = await call('tdarr_library_add', { host: 'home', folders: [folder], template: 'movies', scan: true, apply: false });
    const lib = dry.plan[0].now.libraries[0];
    assert.equal(lib.name, 'clips90');
    assert.equal(lib.folder, folder);
    assert.equal(lib.flowId, 'f1');
    assert.equal(lib.totalTranscodeCount, 0);
    assert.equal(lib.priority, 2);

    seen.length = 0;
    const wrong = await call('tdarr_library_add', { host: 'home', folders: [folder], template: 'movies', scan: true, apply: true, planHash: 'deadbeef0000' });
    assert.equal(wrong.mode, 'aborted');
    assert.ok(!seen.some((r) => JSON.parse(r.body || '{}').data?.mode === 'insert'));

    seen.length = 0;
    const done = await call('tdarr_library_add', { host: 'home', folders: [folder], template: 'movies', scan: true, apply: true, planHash: dry.planHash });
    assert.equal(done.mode, 'applied', JSON.stringify(done));
    const writes = seen.filter((r) => r.method === 'POST' && JSON.parse(r.body).data?.mode !== 'getAll');
    assert.equal(writes.length, 2);
    const ins = JSON.parse(writes[0].body);
    assert.equal(ins.data.collection, 'LibrarySettingsJSONDB');
    assert.equal(ins.data.mode, 'insert');
    assert.equal(ins.data.docID, ins.data.obj._id);
    assert.equal(ins.data.obj.folder, folder);
    const scan = JSON.parse(writes[1].body);
    assert.deepEqual(scan.data.scanConfig, { dbID: ins.data.docID, arrayOrPath: folder, mode: 'scanFindNew' });
    assert.equal(writes[0].headers['x-api-key'], 'tdkey');
});

test('tdarr_library_add refuses a folder that already is a library', async () => {
    const dry = await call('tdarr_library_add', { host: 'home', folders: ['/media/movies'], template: 'Movies', names: ['Movies2'], apply: false });
    assert.ok(dry.blocked.some((b: string) => /already the folder of library "Movies"/.test(b)));
});

test('an API error fails the step (and is journaled as failed)', async () => {
    tdarrLibs.push({ _id: 'FAIL', name: 'Broken', folder: '/broken', cache: '', output: '', priority: 3, flowId: '', totalTranscodeCount: 0, folderWatching: false });
    const dry = await call('tdarr_scan', { host: 'home', library: 'broken', apply: false });
    const res = await call('tdarr_scan', { host: 'home', library: 'broken', apply: true, planHash: dry.planHash });
    assert.equal(res.mode, 'stopped');
    assert.match(res.results[0].output, /HTTP 1 500/);
    const j = await call('journal_list', { host: 'home', limit: 1 });
    assert.equal(j.entries[0].ok, false);
    assert.equal(j.entries[0].tool, 'tdarr_scan');
});
