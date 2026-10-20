import { AsyncLocalStorage } from 'node:async_hooks';
import crypto from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Output, ToolResponse } from '../core/output.js';

export type { ToolResponse };

const current = new AsyncLocalStorage<string>();
let output: Output | null = null;

/** Every registered tool, for the CLI (`mia tools`, `mia call`) and docs generation. */
export const registry = new Map<string, { description: string; readonly: boolean; handler: (args: Record<string, unknown>) => Promise<ToolResponse>; schema: Record<string, unknown> }>();

let registeringWrite = false;

/** Mark the tools registered inside fn as write tools (for docs / `mia tools`). */
export function writeTools(fn: () => void) {
    registeringWrite = true;
    try {
        fn();
    } finally {
        registeringWrite = false;
    }
}

/**
 * Route every tool handler through one place: remember the tool name (used to name
 * spill files), apply the shared output policy, and keep a registry for the CLI.
 */
export function instrument(server: McpServer, out: Output) {
    output = out;
    const orig = server.tool.bind(server) as (...a: unknown[]) => unknown;
    (server as unknown as { tool: (...a: unknown[]) => unknown }).tool = (...args: unknown[]) => {
        const name = args[0] as string;
        const description = typeof args[1] === 'string' ? (args[1] as string) : '';
        const schema = (args.find((a, i) => i > 0 && a && typeof a === 'object') ?? {}) as Record<string, unknown>;
        const cb = args[args.length - 1] as (...a: unknown[]) => Promise<ToolResponse>;
        const wrapped = (...cbArgs: unknown[]) => current.run(name, () => cb(...cbArgs));
        args[args.length - 1] = wrapped;
        registry.set(name, { description, readonly: !registeringWrite, handler: (a) => wrapped(a) as Promise<ToolResponse>, schema });
        return orig(...args);
    };
}

function out(): Output {
    if (!output) throw new Error('output policy not initialised');
    return output;
}

/** Run a tool body and wrap the outcome as an MCP response (redacted, size-guarded). */
export async function run(fn: () => Promise<unknown>): Promise<ToolResponse> {
    return out().run(current.getStore() ?? 'result', fn);
}

/** sha256 of a script as mia downloads it now: it goes into the plan, and the host runs only that file (FETCH_CHECKED). */
export async function urlSha256(url: string): Promise<string> {
    const r = await fetch(url, { signal: AbortSignal.timeout(20_000) });
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    return crypto.createHash('sha256').update(Buffer.from(await r.arrayBuffer())).digest('hex');
}

/** Download $URL to /tmp/mia-tuning.sh and refuse it unless its sha256 is $SHA. */
export const FETCH_CHECKED = 'curl -fsSL "$URL" -o /tmp/mia-tuning.sh && echo "$SHA  /tmp/mia-tuning.sh" | sha256sum -c --quiet';
