import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

let cached: string | undefined;

/** The page of `mia web` (src/web/page.html → dist/web/page.html): a real HTML file, not a string in code. */
export function page(): string {
    if (cached) return cached;
    for (const u of [new URL('./web/page.html', import.meta.url), new URL('./page.html', import.meta.url)]) {
        const p = fileURLToPath(u);
        if (fs.existsSync(p)) return (cached = fs.readFileSync(p, 'utf8'));
    }
    throw new Error('page.html not found next to the server');
}
