#!/usr/bin/python3

# Copyright (c) 2025 Thomas Erbesdobler <t.erbesdobler@gmx.de>
# 
# SPDX-License-Identifier: MIT

import json
import os
import subprocess
import sys


def main():
    dev = sys.argv[1]

    brdesc = os.environ['VMS2_BR_IFUP_DESC']
    brdesc = brdesc.split('-')
    brname = brdesc[0]
    brdesc = brdesc[1:]
    brdesc = {
            e.split('.')[0]: (e.split('.')[1], int(e.split('.')[2])) for e in brdesc
    }

    mac, vlan = brdesc[dev]

    print("Attaching tap-device %s to %s with VLAN/PVID %d." % (dev, brname, vlan))
    subprocess.run(['/sbin/ip', 'link', 'set', dev, 'master', brname]).check_returncode()

    subprocess.run(['/sbin/bridge', 'vlan', 'add',
                    'vid', str(vlan), 'dev', dev, 'pvid', 'untagged']).check_returncode()

    if vlan != 1:
        subprocess.run(['/sbin/bridge', 'vlan', 'del', 'vid', '1', 'dev', dev]).check_returncode()

    subprocess.run(['/sbin/ip', 'link', 'set', dev, 'up']).check_returncode()


if __name__ == '__main__':
    main()
    sys.exit(0)
