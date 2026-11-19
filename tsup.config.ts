import { defineConfig } from 'tsup';

export default defineConfig({
    entry: ['src/cli.ts'],
    format: ['esm'],
    target: 'node22',
    outDir: 'dist',
    clean: true,
    onSuccess: 'mkdir -p dist/scripts && cp src/scripts/*.sh src/scripts/*.py dist/scripts/',
    splitting: false,
    sourcemap: true,
    dts: false,
    banner: {
        js: '#!/usr/bin/env node',
    },
});
