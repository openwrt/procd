#!/usr/bin/ucode
// wait-event.uc <type> <service> <command> [args...]

'use strict';

import * as ubus from 'ubus';
import * as uloop from 'uloop';

let event_type = ARGV[0];
let service = ARGV[1];
let cmd = slice(ARGV, 2);
let status = 1;

uloop.init();

let sub = ubus.subscriber(function(req) {
	if (req.type != event_type || req.data?.service != service)
		return;

	printf("%J\n", req.data);
	status = 0;
	uloop.end();
});

if (!sub || !sub.subscribe('service'))
	die(`cannot subscribe to service: ${ubus.error()}\n`);

let proc = uloop.process(cmd[0], slice(cmd, 1), null, function(code) {
	if (code == 0)
		return;

	warn(`${cmd[0]} exited with ${code}\n`);
	uloop.end();
});

if (!proc)
	die(`cannot run ${cmd[0]}: ${uloop.error()}\n`);

uloop.run();
exit(status);
