import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Live progress of a tool call, for whoever runs it and wants to show it (the console): which hosts
 * are about to be worked on, and each host starting and finishing. Scoped per call, so concurrent
 * MCP calls never see each other's events; nobody listening costs nothing.
 */
export type Progress =
    | { kind: 'hosts'; phase: 'probe' | 'apply'; hosts: string[] }
    | { kind: 'host'; host: string; state: 'run' | 'ok' | 'fail'; note?: string; ms?: number; row?: Record<string, unknown> };

const als = new AsyncLocalStorage<(e: Progress) => void>();

export function withProgress<T>(listener: (e: Progress) => void, fn: () => Promise<T>): Promise<T> {
    return als.run(listener, fn);
}

export function report(e: Progress) {
    const l = als.getStore();
    if (!l) return;
    try {
        l(e);
    } catch {
        /* a drawing problem never breaks the work */
    }
}
