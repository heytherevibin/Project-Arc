@echo off
REM Wrapper to run npm without NPM_CONFIG_DEVDIR (avoids "Unknown env config devdir" warning).
REM Usage: npmw.cmd run type-check   or   npmw.cmd install
set npm_config_devdir=
npm %*
