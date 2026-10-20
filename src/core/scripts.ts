import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const cache = new Map<string, string>();

/**
 * Bash scripts shipped with the server (src/scripts → dist/scripts). Kept as real .sh
 * files so they can be read, shellchecked and run by hand, not escaped into strings.
 */
export function script(name: string): string {
    const hit = cache.get(name);
    if (hit) return hit;
    const candidates = [new URL(`./scripts/${name}`, import.meta.url), new URL(`../scripts/${name}`, import.meta.url)];
    for (const c of candidates) {
        const p = fileURLToPath(c);
        if (fs.existsSync(p)) {
            const text = fs.readFileSync(p, 'utf8');
            cache.set(name, text);
            return text;
        }
    }
    throw new Error(`bundled script ${name} not found (looked in ${candidates.map((c) => fileURLToPath(c)).join(', ')})`);
}
