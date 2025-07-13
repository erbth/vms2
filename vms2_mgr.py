#!/usr/bin/python3

# Copyright (c) 2025 Thomas Erbesdobler <t.erbesdobler@gmx.de>
#
# SPDX-License-Identifier: MIT

import asyncio
import dataclasses
import json
import logging
import os
import signal
import socket
import sys
import vms2


@dataclasses.dataclass
class _VMDesc:
    name: str
    proc: ...
    watcher: ...
    spice_port: int
    spice_password: str


class VMS2Mgr:
    def __init__(self):
        # VM processes
        self._vms = {}

        # Communication socket
        if not os.path.exists("/run/vms2"):
            os.mkdir("/run/vms2", 0o755)

        if os.path.exists("/run/vms2/mgr.sock"):
            os.unlink("/run/vms2/mgr.sock")
            
        self._listening_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._listening_socket.setblocking(False)
        self._listening_socket.bind("/run/vms2/mgr.sock")
        self._listening_socket.listen(50)


    def signal_handler(self):
        asyncio.create_task(self.stop())


    async def init(self):
        # Setup signal handlers
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, self.signal_handler)
        loop.add_signal_handler(signal.SIGINT, self.signal_handler)

        loop.create_task(self.comm_loop())

        logging.info("vms2 mgr is ready")


    # Communication protocol
    async def comm_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            conn,addr = await loop.sock_accept(self._listening_socket)
            loop.create_task(self.client_handler(conn))


    async def client_handler(self, conn):
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.sock_recv(conn, 65536)
            if not data:
                break

            msg = json.loads(data.decode())
            resp = await self.handle_msg(msg)
            await loop.sock_sendall(conn, json.dumps(resp, indent=4).encode())


    async def handle_msg(self, msg):
        match msg['cmd']:
            case "list-running":
                return {
                    'status': 'success',
                    'running-vms': [{
                        'name': n,
                        'spice_port': s_port,
                        'spice_password': s_pass
                    } for n, s_port, s_pass in self.get_running()]
                }

            case "start":
                try:
                    await self.start(msg['vm_name'])
                    return {'status': 'success'}

                except vms2.VMS2Exception as exc:
                    return {'status': 'error', 'msg': str(exc)}

            case "kill":
                try:
                    self.kill(msg['vm_name'])
                    return {'status': 'success'}

                except vms2.VMS2Exception as exc:
                    return {'status': 'error', 'msg': str(exc)}
            
            case _:
                raise RuntimeError(f"Invalid command from client: `{msg['cmd']}'")


    # VM management
    def get_running(self):
        return [(v.name, v.spice_port, v.spice_password) for v in self._vms.values()]


    async def child_watcher(self, name, proc):
        if await proc.wait() != 0:
            logger.warn(f"Failed to run vm `{name}'")

        del self._vms[name]

        
    async def start(self, name):
        if name in self._vms:
            raise vms2.VMS2Exception("VM already running")

        proc, spice_port, spice_password = await vms2.run_vm(name)
        self._vms[name] = _VMDesc(
            name,
            proc,
            asyncio.create_task(self.child_watcher(name, proc)),
            spice_port = spice_port,
            spice_password = spice_password)


    def kill(self, name):
        if name not in self._vms:
            raise vms2.VMS2Exception("VM not running")

        self._vms[name].proc.terminate()


    async def stop(self):
        logging.info("vms2 mgr is stopping...")

        # Kill vms
        #vms = list(self._vms)
        #for n in vms:
        #    self.kill(n)

        # Cancel all tasks
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)

        # Request loop to stop
        asyncio.get_running_loop().stop()


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    loop = asyncio.new_event_loop()

    # Required for use of asyncio with subprocesses
    asyncio.get_child_watcher().attach_loop(loop)

    mgr = VMS2Mgr()

    loop.create_task(mgr.init())
    loop.run_forever()


if __name__ == '__main__':
    main()
    sys.exit(0)
