import { defineConfig } from 'tsup';

export default defineConfig({
    entry: ['src/cli.ts'],
    format: ['esm'],
    target: 'node22',
    outDir: 'dist',
    clean: true,
    onSuccess: 'mkdir -p dist/scripts dist/web && cp src/scripts/*.sh src/scripts/*.py dist/scripts/ && cp src/web/page.html dist/web/',
    splitting: false,
    sourcemap: true,
    dts: false,
    banner: {
        js: '#!/usr/bin/env node',
    },
});
