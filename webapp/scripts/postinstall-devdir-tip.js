#!/usr/bin/env node
/**
 * If NPM_CONFIG_DEVDIR is set (e.g. by Cursor), print a one-line tip after install.
 * This runs as postinstall; it does not modify env or fail the install.
 */
if (process.env.npm_config_devdir !== undefined) {
  console.log('\n  Tip: To avoid the "Unknown env config devdir" warning, use ./npmw instead of npm (e.g. ./npmw run dev)\n');
}
