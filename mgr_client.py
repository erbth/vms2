"""
Client for interacting with vms2_mgr through its UNIX domain socket
"""

# Copyright (c) 2025 Thomas Erbesdobler <t.erbesdobler@gmx.de>
# 
# SPDX-License-Identifier: MIT

import json
import socket
import vms2


def _cmd(cmd, **kwargs):
    # Connect to mgr
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        conn.connect('/run/vms2/mgr.sock')

        # Send command
        conn.send(json.dumps({'cmd': cmd, **kwargs}, indent=4).encode())

        # Receive response
        resp = json.loads(conn.recv(65536).decode())
        if resp.get('status', '<protocol error>') != 'success':
            raise vms2.VMS2Exception(f"{resp.get('msg', '<none>')}")

        return resp

    finally:
        conn.close()


def list_running():
    ret = _cmd('list-running')
    return ret['running-vms']


def start(name):
    _cmd('start', vm_name=name)


def kill(name):
    _cmd('kill', vm_name=name)
