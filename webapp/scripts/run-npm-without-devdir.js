#!/usr/bin/env node
/**
 * Run npm without NPM_CONFIG_DEVDIR in the environment.
 * This avoids the "Unknown env config devdir" warning when the variable
 * is set by the environment (e.g. Cursor IDE).
 *
 * Usage: node scripts/run-npm-without-devdir.js [npm args...]
 * Example: node scripts/run-npm-without-devdir.js run type-check
 */

const { spawnSync } = require('child_process');
const env = { ...process.env };
delete env.npm_config_devdir;
const result = spawnSync('npm', process.argv.slice(2), {
  stdio: 'inherit',
  shell: true,
  env,
});
process.exit(result.status ?? 1);
