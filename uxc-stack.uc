'use strict';

import { readfile, writefile, unlink, mkdir, rmdir, lsdir, chmod } from 'fs';
const ubus = require('ubus');

const REG_DIR   = '/tmp/run/uvol/.meta/uxc';
const META_DIR  = '/tmp/run/uvol/.meta';
const STACK_DIR = '/usr/share/uxc/stacks';

let action = ARGV[0];
let app    = ARGV[1];
let hosts_file = null;

if (action != 'up' && action != 'down' || !app)
	die('usage: uxc-stack <up|down> <app>');

function read_json(path) {
	let raw = readfile(path);
	return raw ? json(raw) : null;
}

function uxc(...args) {
	let rc = system([ 'uxc', ...args ]);
	if (rc != 0)
		printf('uxc-stack: uxc %s -> %d\n', join(' ', args), rc);
	return rc;
}

function qname(name) {
	return app + '.' + name;
}


let comp = { instances: [], secrets: {} };

let api = {
	instance: function(name, spec) {
		spec ??= {};
		spec.name = name;
		push(comp.instances, spec);
		return spec;
	},

	generate: function(scope) {
		comp.secrets[scope] = true;
		return 'generate@' + app + '/' + scope;
	},
};

function compose_stack() {
	let tmpl_path = STACK_DIR + '/' + app + '.uc';
	let prog = loadfile(tmpl_path);
	if (!prog)
		die('uxc-stack: cannot load stack template ' + tmpl_path);
	let compose = prog();
	if (type(compose) != 'function')
		die('uxc-stack: ' + tmpl_path + ' must return a compose(api) function');
	compose(api);
}

function stack_members() {
	let out = [];
	for (let e in (lsdir(REG_DIR) ?? [])) {
		if (substr(e, -5) != '.json')
			continue;
		let reg = read_json(REG_DIR + '/' + e);
		if (reg && reg.origin == 'stack:' + app)
			push(out, reg);
	}
	return out;
}


function fnv1a(s) {
	let h = 2166136261;
	for (let i = 0; i < length(s); i++) {
		h ^= ord(s, i);
		h = (h * 16777619) & 0xffffffff;
	}
	return h;
}

function idmap_offset(qn) {
	return ((fnv1a(qn) % 0x7000) + 1) * 0x10000;
}

function backhaul_net() {
	let slot = fnv1a(app) % 512;
	return sprintf('198.%d.%d', 18 + (slot >> 8), slot & 0xff);
}

function build_registration(inst) {
	if (!inst.image)
		die('uxc-stack: instance ' + inst.name + ' declares no image');

	let img = read_json(REG_DIR + '/' + inst.image + '.json');
	if (!img)
		die('uxc-stack: image "' + inst.image + '" not installed (need container-' + inst.image + ')');

	let reg = {
		name: qname(inst.name),
		image: img.image,
		'image-digest': img['image-digest'],
		path: img.path,
		origin: 'stack:' + app,
		autostart: true,
	};

	if (length(inst.volumes)) {
		let vols = [];
		for (let v in inst.volumes) {
			let p = split(v, ':');
			push(vols, { name: p[0], mountpoint: p[1], size: p[2] });
		}
		reg['data-volumes'] = vols;
	}
	if (inst.overlay)
		reg['temp-overlay-size'] = inst.overlay;
	else if (img['temp-overlay-size'])
		reg['temp-overlay-size'] = img['temp-overlay-size'];
	else if (img['overlay-size'])
		reg['overlay-size'] = img['overlay-size'];
	if (inst.env)
		reg.initenv = inst.env;

	let prov = [];
	if (inst.provision || inst.secrets) {
		let pdir = META_DIR + '/stacks/' + app + '/' + inst.name;
		mkdir(META_DIR + '/stacks/' + app, 0700);
		mkdir(pdir, 0700);
		for (let dest in (inst.provision ?? {})) {
			let src = pdir + '/' + replace(dest, /[^A-Za-z0-9._-]/g, '_');
			if (writefile(src, inst.provision[dest]) == null)
				die('uxc-stack: cannot write provisioned file ' + src);
			chmod(src, 0644);
			push(prov, { source: src, destination: dest });
		}
		for (let dest in (inst.secrets ?? {}))
			push(prov, { source: META_DIR + '/secrets/' + app + '/' +
				     inst.secrets[dest] + '/value', destination: dest, secret: true });
	}
	if (length(prov))
		reg.provision = prov;

	reg['idmap-offset'] = sprintf('%d', idmap_offset(reg.name));

	if (hosts_file)
		reg['hosts-file'] = hosts_file;

	return reg;
}

function instance_up(inst) {
	let reg = build_registration(inst);
	let path = REG_DIR + '/' + reg.name + '.json';
	if (writefile(path, sprintf('%.J\n', reg)) == null)
		die('uxc-stack: cannot write ' + path);
}

function bringup() {
	ubus.call({ object: 'service', method: 'event',
		    data: { type: 'uxc.bringup', data: {} } });
	let err = ubus.error();
	if (err)
		die('uxc-stack: cannot trigger bring-up: ' + err);
}


function backhaul_prepare() {
	let net = backhaul_net();
	let hdir = META_DIR + '/stacks/' + app;
	let hosts = '127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n';
	let i = 0, ordered, inst, side;

	ordered = sort(comp.instances, function(a, b) {
		return (a.name < b.name) ? -1 : (a.name > b.name) ? 1 : 0;
	});
	for (inst in ordered) {
		inst.bh_address = net + '.' + (i + 1);
		hosts += inst.bh_address + '\t' + inst.name + '\n';
		i++;
	}

	mkdir(META_DIR + '/stacks', 0700);
	mkdir(hdir, 0700);
	writefile(hdir + '/hosts', hosts);
	hosts_file = hdir + '/hosts';

	for (inst in comp.instances) {
		side = {
			'org.openwrt.network.backhaul': app,
			'org.openwrt.network.backhaul-address': inst.bh_address,
		};
		if (inst.access) {
			let f = split(inst.access, ' ');
			side['org.openwrt.network.attach'] = f[0];
			for (let n = 1; n < length(f); n++) {
				let kv = split(f[n], '=');
				if (kv[0] == 'egress')
					side['org.openwrt.network.egress'] = kv[1];
				else if (kv[0] == 'ingress')
					side['org.openwrt.network.ingress'] = kv[1];
				else if (kv[0] == 'host')
					side['org.openwrt.network.host'] = kv[1];
			}
		}
		writefile(REG_DIR + '/' + qname(inst.name) + '.annotations', sprintf('%J\n', side));
	}
}


if (action == 'up') {
	compose_stack();
	backhaul_prepare();
	for (let inst in comp.instances)
		instance_up(inst);
	bringup();
} else {
	let members = stack_members();
	let kept = [];

	for (let reg in members) {
		let krc = system([ 'uxc', 'kill', reg.name ]);
		if (krc != 0 && krc != 254)
			printf('uxc-stack: uxc kill %s -> %d\n', reg.name, krc);
		uxc('delete', reg.name);
		unlink(REG_DIR + '/' + reg.name + '.json');
		unlink(REG_DIR + '/' + reg.name + '.annotations');
		system([ 'rm', '-rf', META_DIR + '/uxc/state/' + reg.name ]);
		for (let v in (reg['data-volumes'] ?? []))
			push(kept, reg.name + '.' + v.name);
	}

	unlink(META_DIR + '/stacks/' + app + '/hosts');
	rmdir(META_DIR + '/stacks/' + app);

	let secrets = lsdir(META_DIR + '/secrets/' + app) ?? [];

	if (length(kept)) {
		warn('uxc-stack: kept data volume(s) for ' + app +
		     '; remove manually if the data is no longer needed:\n');
		for (let vn in kept)
			warn('  uvol remove ' + vn + '\n');
	}
	if (length(secrets)) {
		warn('uxc-stack: kept generated secret(s) for ' + app +
		     ' (paired with the data above; reused on reinstall); remove with:\n');
		warn('  rm -rf ' + META_DIR + '/secrets/' + app + '\n');
	}
}
