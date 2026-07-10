#!/usr/bin/env python3
"""Minimal os-ken application launcher.

Ubuntu's python3-os-ken package ships the os_ken library but not the
os-ken-manager / ryu-manager CLI (its os_ken/cmd package is not part of
the distro build). This script replicates that CLI's bootstrap so the
project's controller apps can still be launched the usual way:

    python3 controller/osken_manager.py <app.module.path> [<app2.module.path> ...]
"""
import logging
import sys

from os_ken.base.app_manager import AppManager


def main(argv):
    if not argv:
        print(f"usage: {sys.argv[0]} <app_module> [<app_module> ...]")
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    )
    AppManager.run_apps(argv)


if __name__ == '__main__':
    main(sys.argv[1:])
