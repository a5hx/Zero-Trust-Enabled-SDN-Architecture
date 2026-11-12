#!/usr/bin/env python3
"""Minimal os-ken application launcher.

Ubuntu's python3-os-ken package ships the os_ken library but not the
os-ken-manager / ryu-manager CLI (its os_ken/cmd package is not part of
the distro build). This script replicates that CLI's bootstrap so the
project's controller apps can still be launched the usual way:

    python3 controller/osken_manager.py [--ofp-port N] <app.module.path> [<app2.module.path> ...]
"""
import logging
import sys

# Must happen before anything imports socket/select, and before app_manager is
# imported at all -- os_ken.lib.hub defines monkey patching but never applies it
# on import, so a launcher that skips this gets green threads running on real
# blocking sockets. The first hub.spawn'd task to make a blocking call (here:
# the northbound API's serve_forever) then pins the OS thread and the eventlet
# hub never schedules anything else -- including OFPHandler's OpenFlowController,
# which is what binds the OpenFlow port. Symptom is a controller that serves its
# REST API fine while no switch can ever connect. os_ken/cmd/manager.py does the
# same call for the same reason.
#
# Only when run as the program (`python3 -m controller.osken_manager`), where
# this still happens first, exactly as before. A plain import -- the tests
# import parse_args -- must not monkey-patch the importing process: under
# pytest that greened every later test's sockets and threads, and the suite
# hung on the first real socket wait.
if __name__ == '__main__':
    from os_ken.lib import hub

    # Two calls, not one, and the order matters. eventlet.monkey_patch() treats
    # any explicit True as "patch only these", so patch(thread=True) alone
    # would green threading and leave socket/select/time real. The first call
    # (thread=False) therefore patches everything except threading; the
    # second adds threading.
    hub.patch(thread=False)
    hub.patch(thread=True)

from os_ken.base.app_manager import AppManager  # noqa: E402


def parse_args(argv):
    """(ofp_port or None, app modules). `--ofp-port N` is the only option:
    it lets a second controller (controller/auditor.py) listen beside the
    primary on one machine. Absent, os-ken's default (6653) is unchanged."""
    port = None
    apps = []
    it = iter(argv)
    for a in it:
        if a == '--ofp-port' or a.startswith('--ofp-port='):
            val = a.split('=', 1)[1] if '=' in a else next(it, None)
            if val is None or not val.isdigit() or not 0 < int(val) < 65536:
                raise SystemExit(f'--ofp-port needs a TCP port, got {val!r}')
            port = int(val)
        else:
            apps.append(a)
    return port, apps


def main(argv):
    port, argv = parse_args(argv)
    if not argv:
        print(f"usage: {sys.argv[0]} [--ofp-port N] <app_module> [<app_module> ...]")
        sys.exit(1)
    if port is not None:
        # Registered by os_ken.controller.controller, which AppManager's import
        # above has already loaded; set before any app starts listening.
        from os_ken import cfg as os_ken_cfg
        os_ken_cfg.CONF.set_override('ofp_tcp_listen_port', port)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    )
    AppManager.run_apps(argv)


if __name__ == '__main__':
    main(sys.argv[1:])
