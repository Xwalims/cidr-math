#!/usr/bin/env node
'use strict';

process.exitCode = require('../src/cli.js').main(process.argv.slice(2));