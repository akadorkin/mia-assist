import { z } from 'zod';
import { HIDDEN, PARAM_RU } from '../labels.js';

/** A tool parameter as the web form draws it. */
export interface Field {
    name: string;
    kind: 'string' | 'number' | 'boolean' | 'enum' | 'list' | 'json';
    options?: string[];
    default?: unknown;
    required: boolean;
    hint: string;
    hidden: boolean;
}

const unwrap = (t: z.ZodTypeAny): z.ZodTypeAny => {
    while (t instanceof z.ZodDefault || t instanceof z.ZodOptional || t instanceof z.ZodNullable || t instanceof z.ZodEffects) t = t instanceof z.ZodEffects ? t._def.schema : t._def.innerType;
    return t;
};

function kindOf(t: z.ZodTypeAny): Pick<Field, 'kind' | 'options'> {
    const b = unwrap(t);
    if (b instanceof z.ZodEnum) return { kind: 'enum', options: b.options as string[] };
    if (b instanceof z.ZodBoolean) return { kind: 'boolean' };
    if (b instanceof z.ZodNumber) return { kind: 'number' };
    if (b instanceof z.ZodString) return { kind: 'string' };
    if (b instanceof z.ZodArray) return { kind: 'list' };
    // «a,b» on the console or an array over MCP (listParam)
    if (b instanceof z.ZodUnion && (b.options as z.ZodTypeAny[]).some((o) => unwrap(o) instanceof z.ZodArray) && (b.options as z.ZodTypeAny[]).some((o) => unwrap(o) instanceof z.ZodString)) return { kind: 'list' };
    return { kind: 'json' };
}

export function fieldsOf(shape: Record<string, unknown>): Field[] {
    return Object.entries(shape)
        .filter(([k]) => k !== 'apply' && k !== 'planHash')
        .map(([name, raw]) => {
            const t = raw as z.ZodTypeAny;
            const def = t instanceof z.ZodDefault ? (t._def.defaultValue as () => unknown)() : undefined;
            return { name, ...kindOf(t), ...(def !== undefined ? { default: def } : {}), required: !t.isOptional(), hint: PARAM_RU[name] ?? t.description ?? '', hidden: HIDDEN.has(name) };
        });
}
