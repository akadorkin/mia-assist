import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { ScenarioEngine } from '../core/scenario.js';
import { run, writeTools } from './helpers.js';

export function registerScenarioTools(server: McpServer, ctx: Ctx, engine: ScenarioEngine) {
    server.tool(
        'scenario_list',
        'Runbooks for whole operations (add a node and bring it to the fleet standard, switch the ingress, remove a node, change xray rules): their parameters, and the runs started so far. With run: the step log of that run.',
        { run: z.string().optional() },
        (args) =>
            run(async () => {
                if (args.run) return engine.load(args.run);
                return { scenarios: engine.list(), runs: engine.runs().slice(0, 20) };
            }),
    );

    writeTools(() => {
        server.tool(
            'scenario_start',
            'Start a runbook. Read-only checks run on their own; the first step that changes something comes back with its exact plan (dry run) and waits. Show that plan to the owner and continue with scenario_step only after the owner said yes to that step.',
            {
                scenario: z.string(),
                params: z.record(z.unknown()).default({}),
            },
            (args) => run(() => engine.start(args.scenario, args.params)),
        );

        server.tool(
            'scenario_step',
            'Answer the step a run is waiting on: apply (run the plan shown — only with the owner\'s explicit yes for this step), done (a manual step the owner has finished), skip, or retry (re-check / re-plan). Returns what happened and the next step that needs an answer. Runs are saved: resume any time with decision retry.',
            {
                run: z.string(),
                decision: z.enum(['apply', 'done', 'skip', 'retry']),
                params: z.record(z.unknown()).optional().describe('change parameters of the run first (e.g. the sniMap a step asked for); the step is then re-checked instead of decided'),
            },
            (args) => run(() => (args.params ? engine.setParams(args.run, args.params) : engine.decide(args.run, args.decision))),
        );
    });
    void ctx;
}
