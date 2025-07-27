#!/usr/bin/python3

# Copyright (c) 2025 Thomas Erbesdobler <t.erbesdobler@gmx.de>
# 
# SPDX-License-Identifier: MIT

import argparse
import asyncio
import logging
import signal
import sys
import vms2


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("name", metavar="<name>", type=str)

    parser.add_argument("--isoimg", type=str, help="ISO image to boot from")

    return parser.parse_args()


async def _run_vm(args):
    def _ready_cb(proc, spice_port, spice_password):
        pass

    await vms2.run_vm(args.name, _ready_cb, args.isoimg)

    
def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    # Ignore SIGINT and SIGTERM s.t. they are handled by the qemu process only
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    args = parse_args()

    # Required for use of asyncio with subprocesses
    loop = asyncio.new_event_loop()
    asyncio.get_child_watcher().attach_loop(loop)
    loop.run_until_complete(_run_vm(args))


if __name__ == '__main__':
    try:
        main()
        sys.exit(0)

    except vms2.VMS2Exception as exc:
        print("Error: %s" % exc)
        sys.exit(1)
