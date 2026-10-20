import fs from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

/**
 * Panel writes stay in mcp-remnawave (its plan/apply, backups and journal). Scenarios that need
 * the panel start it as a child MCP server and call its tools — the same tools Claude would call.
 * MIA_REMNAWAVE_MCP = the command that runs it, e.g. "node /Users/me/src/mcp-remnawave/dist/index.js";
 * it inherits REMNAWAVE_BASE_URL / REMNAWAVE_API_TOKEN … from mia's environment.
 */
export interface PanelCallResult {
    ok: boolean;
    /** Parsed JSON when the tool answered JSON, else the text. */
    data: unknown;
    text: string;
}

export class RemnawaveBridge {
    private client?: Client;
    private connecting?: Promise<Client>;

    constructor(private command: string[]) {}

    static from(raw: string | undefined): RemnawaveBridge | undefined {
        raw = raw?.trim();
        if (!raw) return undefined;
        const cmd = raw.startsWith('[') ? (JSON.parse(raw) as string[]) : raw.split(/\s+/);
        return new RemnawaveBridge(cmd);
    }

    private async connect(): Promise<Client> {
        if (this.client) return this.client;
        this.connecting ??= (async () => {
            const [command, ...args] = this.command;
            const transport = new StdioClientTransport({ command, args, env: { ...process.env, REMNAWAVE_MAX_OUTPUT_CHARS: '5000000' } as Record<string, string>, stderr: 'ignore' });
            const client = new Client({ name: 'mia-scenarios', version: '1' });
            await client.connect(transport);
            this.client = client;
            return client;
        })();
        return this.connecting;
    }

    async tools(): Promise<string[]> {
        const c = await this.connect();
        return (await c.listTools()).tools.map((t) => t.name);
    }

    async call(name: string, args: Record<string, unknown>): Promise<PanelCallResult> {
        const c = await this.connect();
        const res = (await c.callTool({ name, arguments: args }, undefined, { timeout: 300_000 })) as { content?: Array<{ type: string; text?: string }>; isError?: boolean };
        const text = (res.content ?? []).map((x) => x.text ?? '').join('\n');
        return { ok: !res.isError, data: unspill(parseJson(text)), text };
    }

    async close() {
        await this.client?.close().catch(() => undefined);
        this.client = undefined;
        this.connecting = undefined;
    }
}

export function parseJson(text: string): unknown {
    try {
        return JSON.parse(text);
    } catch {
        return text;
    }
}

/** Oversized tool results are saved to a file with a summary in their place: read the file back when it is local. */
export function unspill(data: unknown): unknown {
    const d = data as { truncated?: boolean; savedTo?: string } | null;
    if (d && typeof d === 'object' && d.truncated && typeof d.savedTo === 'string' && fs.existsSync(d.savedTo)) {
        try {
            return JSON.parse(fs.readFileSync(d.savedTo, 'utf8'));
        } catch {
            return data;
        }
    }
    return data;
}
