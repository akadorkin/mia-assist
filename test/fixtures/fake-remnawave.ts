// A stand-in for mcp-remnawave over stdio: the same tool names and plan/apply answers, no panel.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const server = new McpServer({ name: 'fake-remnawave', version: '0' });
const text = (d: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(d) }] });
let written = 0;
server.tool('config_profiles_list', 'list', {}, async () => text([{ name: 'profile-ru', nodes: ['ru-x-ingress1'] }]));
server.tool('nodes_list', 'nodes', { state: z.string().optional(), filter: z.string().optional() }, async () => text({ total: 0, nodes: [] }));
server.tool(
    'config_profile_patch',
    'patch',
    { profile: z.string(), ops: z.array(z.record(z.unknown())), apply: z.boolean().default(false), planHash: z.string().optional() },
    async (a) => {
        if (!a.apply) {
            // a big dry run: spilled to a file like the real server does past its output limit
            const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fake-rw-')), 'plan.json');
            fs.writeFileSync(file, JSON.stringify({ mode: 'dry-run', planHash: 'abc123', changed: 1, report: [{ ops: a.ops }] }));
            return text({ truncated: true, savedTo: file });
        }
        if (a.planHash !== 'abc123') return text({ mode: 'aborted' });
        written++;
        return text({ mode: 'applied', written });
    },
);
server.tool('boom', 'error', {}, async () => ({ content: [{ type: 'text' as const, text: 'Error: nope' }], isError: true }));
await server.connect(new StdioServerTransport());
