#!/usr/bin/ucode -R

import { readfile, writefile, basename, unlink } from 'fs';

const ACT_KILL = 'SCMP_ACT_KILL_PROCESS';
const ACT_ALLOW = 'SCMP_ACT_ALLOW';

function usage(name) {
	if (name == 'trace2seccomp')
		warn("usage: trace2seccomp [--merged|--two-phase] [-o out.json] <trace.ndjson>\n");
	else
		warn(sprintf("usage: %s <program> [args...]\n", name));
	exit(1);
}

function shq(s) {
	return "'" + replace(s, "'", "'\\''") + "'";
}

function invoked_name() {
	let cmd = readfile('/proc/self/cmdline');
	if (!cmd)
		return basename(sourcepath());

	let parts = split(cmd, '\x00');
	while (length(parts) && parts[length(parts) - 1] == '')
		pop(parts);

	let idx = length(parts) - length(ARGV) - 1;
	if (idx < 0)
		return basename(sourcepath());

	return basename(parts[idx]);
}

function collect(ndjson, want_phase) {
	let seen = {};

	for (let line in split(ndjson, '\n')) {
		if (!length(line))
			continue;

		let ev;
		try { ev = json(line); }
		catch (e) { continue; }

		if (type(ev) != 'object' || ev.event != 'syscall' || !ev.syscall)
			continue;
		if (want_phase && ev.phase != want_phase)
			continue;

		seen[ev.syscall] = true;
	}

	return sort(keys(seen));
}

function profile(names) {
	return {
		defaultAction: ACT_KILL,
		syscalls: [ { names: names, action: ACT_ALLOW } ]
	};
}

function emit(obj, outfile) {
	let text = sprintf("%.J\n", obj);

	if (!outfile) {
		print(text);
		return;
	}

	if (writefile(outfile, text) == null)
		die(sprintf("cannot write %s\n", outfile));
}

function run_trace(prog, args) {
	let tmp = sprintf("/tmp/.trace2seccomp.%d.ndjson", time());
	let cmd = "ujail -m trace -M " + shq(tmp) + " -- " + shq(prog);

	for (let a in args)
		cmd += " " + shq(a);

	system(cmd);

	let nd = readfile(tmp);
	unlink(tmp);

	return nd;
}

function run_live(name) {
	if (!length(ARGV))
		usage(name);

	let prog = ARGV[0];
	let nd = run_trace(prog, slice(ARGV, 1));
	if (nd == null)
		die("no trace captured (did ujail run?)\n");

	let out = sprintf("/tmp/%s.%d.json", basename(prog), time());
	emit(profile(collect(nd, 'app')), out);
	warn(sprintf("seccomp profile written to %s\n", out));
}

function run_offline() {
	let merged, two_phase, outfile, infile;
	let i = 0;

	while (i < length(ARGV)) {
		let a = ARGV[i];
		if (a == '--merged')
			merged = true;
		else if (a == '--two-phase')
			two_phase = true;
		else if (a == '-o')
			outfile = ARGV[++i];
		else
			infile = a;
		i++;
	}

	if (!infile)
		usage('trace2seccomp');

	let nd = readfile(infile);
	if (nd == null)
		die(sprintf("cannot read %s\n", infile));

	if (two_phase)
		emit({ predl: profile(collect(nd, null)), postdl: profile(collect(nd, 'app')) }, outfile);
	else if (merged)
		emit(profile(collect(nd, null)), outfile);
	else
		emit(profile(collect(nd, 'app')), outfile);
}

let self = invoked_name();

if (self == 'utrace' || self == 'seccomp-trace')
	run_live(self);
else
	run_offline();
