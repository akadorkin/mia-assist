import fs from 'node:fs';
import { Config } from '../config.js';
import { Host, Inventory } from './inventory.js';
import { why } from './neterr.js';
import { Output } from './output.js';
import { Panel, PanelNode, panelOf } from './panel.js';
import { HostFacts, probeHost } from './probe.js';
import { Transport } from './ssh.js';
import { StateStore } from './state.js';

/** Shared by every tool. The inventory is re-read when fleet.yaml changes on disk. */
export class Ctx {
    readonly transport: Transport;
    readonly out: Output;
    readonly state: StateStore;
    panel?: Panel;
    private inv?: { mtime: number; inv: Inventory };

    constructor(
        readonly config: Config,
        transport?: Transport,
    ) {
        this.transport = transport ?? new Transport(config);
        this.out = new Output(config);
        this.state = new StateStore(config);
        this.panel = panelOf(config);
    }

    private cache = new Map<string, { at: number; mode: 'quick' | 'full'; facts: HostFacts }>();

    /**
     * Facts of a host, probed or — within factsTtlMs — remembered: status → plan → apply → logs reuse one
     * probe. fresh: probe now (status and audit are «check now»). A change on the host forgets it.
     */
    async facts(host: Host, mode: 'quick' | 'full' = 'quick', opts: { fresh?: boolean; timeoutMs?: number } = {}): Promise<HostFacts> {
        const c = this.cache.get(host.name);
        if (!opts.fresh && c && Date.now() - c.at < this.config.factsTtlMs && (c.mode === 'full' || mode === 'quick')) return c.facts;
        const facts = await probeHost(this.transport, host, mode, opts.timeoutMs);
        this.cache.set(host.name, { at: Date.now(), mode, facts });
        return facts;
    }

    /** Forget remembered facts (a host was changed). */
    forget(host?: string) {
        if (host) this.cache.delete(host);
        else this.cache.clear();
    }

    /** After a key or address changed in the console: rebuild the panel client from the (mutated) config. */
    reconfigure() {
        this.panel = panelOf(this.config);
        this.panelError = undefined;
    }

    inventory(): Inventory {
        const file = this.config.inventoryFile;
        const mtime = fs.existsSync(file) ? fs.statSync(file).mtimeMs : 0;
        if (!this.inv || this.inv.mtime !== mtime) this.inv = { mtime, inv: Inventory.load(file) };
        return this.inv.inv;
    }

    /** Panel nodes, or null when the panel is not configured / not answering (reason in panelError). */
    panelError?: string;
    async panelNodes(fresh = false): Promise<PanelNode[] | null> {
        if (!this.panel) return null;
        try {
            this.panelError = undefined;
            return await this.panel.nodes(fresh);
        } catch (e) {
            this.panelError = why(e);
            return null;
        }
    }

    assertWritable() {
        if (this.config.readonly) throw new Error('server is in read-only mode (MIA_READONLY=true)');
    }
}
