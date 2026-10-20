# procd: init system, process supervisor, hotplug daemon and container runtime for OpenWrt

procd is the Linux init system, service manager, hotplug daemon and OCI
container runtime of [OpenWrt](https://openwrt.org/). It is PID 1 on every
device running OpenWrt and on the firmwares derived from it, which puts it
on a very large installed base of routers, access points, switches and
embedded Linux boards. It has been OpenWrt's init since Barrier Breaker
(2014), when it replaced BusyBox init.

procd is written in C against [libubox](https://github.com/openwrt/libubox)
and [ubus](https://github.com/openwrt/ubus). Everything it does at run time
is exposed and driven over ubus: starting and stopping services, reloading
configuration, hotplug events, reboot and system upgrade. There is no
private control socket and no bespoke IPC.

The canonical repository is
[git.openwrt.org/project/procd.git](https://git.openwrt.org/project/procd.git),
mirrored at [github.com/openwrt/procd](https://github.com/openwrt/procd).
User documentation lives in the
[OpenWrt wiki](https://openwrt.org/docs/techref/procd), including the
[init script reference](https://openwrt.org/docs/guide-developer/procd-init-scripts).

## Relation to other init systems

procd supervises long-running services the way runit and s6 do: each
instance is a tracked child, respawned on failure, with its output
captured. Service definitions arrive over ubus from shell init scripts,
so the service manager, the hotplug daemon and the rest of the system
share one IPC mechanism; ubus takes the place that D-Bus and udev hold on
a desktop distribution. There are no unit files and no dependency solver.
Ordering at boot comes from the `S` numbers of the `/etc/rc.d/` symlinks,
and anything after boot is event driven through triggers.

## Features

- **Init and boot.** Early mounts (`/proc`, `/sys`, cgroup2, `/dev`,
  `/tmp`), console setup, early kernel module loading, a preinit stage
  with its own hotplug rules for failsafe and flash recovery, then the
  classic `/etc/inittab` actions (`sysinit`, `respawn`, `askfirst`,
  `askconsole`, `shutdown` and their late variants). `sysinit` runs the
  `/etc/rc.d/S*` scripts through a run queue.
- **Service supervision.** Services are registered over ubus, usually by
  their init script through the `procd_*` shell helpers in OpenWrt's
  `base-files`. Each service has one or more instances with a command
  line, environment, user and group, nice level, resource limits, stdout
  and stderr capture to syslog, a pidfile, a reload signal and a
  termination timeout. Instances are respawned with a configurable
  threshold, interval and retry limit. An instance can be told to restart
  when a configuration file or a network device changes. Every instance
  and every inittab entry runs in a cgroup of its own, so a stop reaches
  every descendant process.
- **Configuration reload without restart.** A service declares triggers
  on configuration or ubus events. `ubus call service event` and
  `reload_config` feed those triggers, and procd compares the registered
  instance against the new one to decide whether a restart is needed.
- **Validation.** Init scripts publish a schema for their UCI
  configuration, and `ubus call service validate` returns it so that
  frontends can check settings before applying them.
- **Hotplug.** procd reads kernel uevents over netlink and matches them
  against JSON rules (`/etc/hotplug.json`). Rule actions create and
  remove device nodes, load firmware, run button handlers and dispatch
  scripts under `/etc/hotplug.d/<subsystem>/`. Each subsystem is also
  reachable as a `hotplug.<subsystem>` ubus object, and `udevtrigger`
  replays uevents for coldplug.
- **Watchdog.** procd feeds the hardware watchdog from the first moments
  of boot, hands the open descriptor from `init` to `procd`, and exposes
  frequency, timeout and magic close over ubus. Per-instance software
  watchdogs can require a service to check in periodically.
- **System control.** The `system` ubus object reports board and system
  information, reboots, signals processes, validates firmware images and
  runs `sysupgrade`. During an upgrade PID 1 hands over to `upgraded`,
  which runs the flash procedure from a ramdisk.
- **SELinux.** Built with `SELINUX`, `init` loads the policy before
  anything else runs, halts if the policy fails to load in enforcing
  mode, and relabels the filesystem when booting from an initramfs.
- **Sandboxing and containers.** `ujail` runs an instance in its own
  mount namespace with only the files it needs, resolving shared library
  dependencies from the ELF headers. It optionally adds network, user,
  cgroup, PID, UTS and IPC namespaces, drops capabilities, applies a
  seccomp filter, `no_new_privs`, cgroup2 resource limits and an eBPF
  device filter. The same binary executes OCI runtime bundles, including
  rootless ones through id-mapped mounts, and wires the container
  network through netifd.
- **Staged seccomp.** A profile written for an application lists the
  syscalls the application needs, yet the dynamic loader and the libc
  start-up code need more, so a filter installed before `execve` has to
  allow them for the lifetime of the process. `ujail` applies the
  profile through ptrace. It stops the workload after `execve`,
  before its first userspace instruction, and injects a filter that
  covers the profile plus what the loader needs. It then runs the
  process to its ELF entry point and stacks a second filter that denies
  the loader's file access calls, and finally runs it to `main()`,
  found through the libc start routine, and stacks a third filter that
  denies the libc initialisation calls. Seccomp filters only ever get
  stricter when stacked, so by the time `main()` runs the live filter
  is exactly the profile. Static binaries get the same treatment in two
  stages, and since the parent injects the filter from outside, no
  preload shim is involved and static binaries are covered too.
  Profiles can be enforced, traced, audited or run in complain mode, and
  `trace2seccomp` turns a syscall trace into an OCI seccomp profile.
- **Containers as a feature of the package manager.** `uxc` manages OCI
  containers with a `runc`-compatible command set and stores their state
  as procd service instances, so `apk` packages can ship containers that
  start at boot, respawn, get data volumes and log to syslog like any
  other service.
- **Small.** procd links against libubox, ubus, json-c and udebug only.
  `ujail` adds libuci and `init` adds libselinux when built with
  `SELINUX`.

## Components

| Binary | Role |
| --- | --- |
| `init` | PID 1 at boot: early mounts, console, kernel modules, preinit, then `exec` of `procd` |
| `procd` | PID 1 for the rest of the uptime: inittab, services, hotplug, watchdog, `system` and `service` ubus objects. Also runs as a standalone hotplug daemon (`-h`) and, built with `DISABLE_INIT`, as a plain service manager under another init |
| `ujail` | Namespace and capability sandbox for service instances and OCI runtime for containers |
| `uxc` | Container management CLI on top of the `container` ubus object |
| `uxc-net`, `uxc-stack` | ucode helpers for container networking through netifd and for multi-container stacks |
| `trace2seccomp` | Builds an OCI seccomp profile from a `ujail` syscall trace |
| `udevtrigger` | Replays kernel uevents for coldplug |
| `upgraded` | Replaces PID 1 during `sysupgrade` and runs the flash procedure |
| `askfirst` | Waits for Enter on a console before executing the shell given as its argument |
| `libsetlbf.so` | `LD_PRELOAD` shim that makes stdout unbuffered so captured service output reaches syslog as it is written |

## ubus interface

| Object | Methods |
| --- | --- |
| `service` | `set`, `add`, `list`, `delete`, `signal`, `event`, `validate`, `get_data`, `set_data`, `state`, `update_start`, `update_complete`, `watchdog` |
| `container` | `set`, `add`, `list`, `delete`, `state`, `respawn_cancel`, `respawn_reset`, `console_set`, `console_attach`, `get_features` |
| `system` | `board`, `info`, `reboot`, `watchdog`, `signal`, `validate_firmware_image`, `sysupgrade` |
| `hotplug.<subsystem>` | `call` |
| `container.<name>` (from `ujail`) | `start`, `state`, `kill`, `delete`, `pause`, `resume`, `reclaim`, `update`, `exec` |

## Building

```
cmake -B build -DJAIL_SUPPORT=1 -DSECCOMP_SUPPORT=1 -DUTRACE_SUPPORT=1
cmake --build build
```

Further options: `DISABLE_INIT` builds procd without the PID 1 parts,
`SELINUX` builds `init` with policy loading, `EARLY_PATH` sets the `PATH`
used during early boot, `DEBUG` enables verbose logging.

## Licence

procd's own sources are under the LGPL-2.1. `udevtrigger` is under the
GPL-2.0-only, the seccomp BPF helpers under the BSD-3-Clause and `rcS.c`
under the ISC licence, so the package as a whole is distributed under the
GPL-2.0-only. See `COPYING` for the per-file breakdown and the full
licence texts.
