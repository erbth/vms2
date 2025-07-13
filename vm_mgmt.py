#!/usr/bin/python3

# Copyright (c) 2025 Thomas Erbesdobler <t.erbesdobler@gmx.de>
# 
# SPDX-License-Identifier: MIT

import argparse
import logging
import sys
import mgr_client
import vms2


def parse_args():
    parser = argparse.ArgumentParser()

    action = parser.add_subparsers(metavar="ACTION", dest="action",
                                   required=True)

    p_list = action.add_parser("list", help="List all vms")

    p_create = action.add_parser("create", help="Create new vm")
    p_create.add_argument(metavar="<name>", dest="name", type=str)
    p_create.add_argument(metavar="<nr cores>", dest="cores", type=int)
    p_create.add_argument(metavar="<memory>", dest="memory", type=str)
    p_create.add_argument("--disk-size", type=str, required=False)
    p_create.add_argument("--encrypt-disk", metavar="<key id>", type=str)

    p_delete = action.add_parser("delete", help="Delete vm")
    p_delete.add_argument(metavar="<name>", dest="name", type=str)

    p_add_nic = action.add_parser("add-nic", help="Add network interface")
    p_add_nic.add_argument(metavar="<name>", dest="name", type=str, help="VM name")
    p_add_nic.add_argument(metavar="<network>", dest="network", type=str)

    p_clone = action.add_parser("clone", help="Clone a vm")
    p_clone.add_argument(metavar="<src name>", dest="src_name", type=str)
    p_clone.add_argument(metavar="<dst name>", dest="dst_name", type=str)

    p_list_networks = action.add_parser("list-networks",
                                       help="List configured networks")

    # Interaction with management daemon
    p_show_running = action.add_parser("list-running",
                                       help="List vms running through manager")

    p_start = action.add_parser("start",
                                help="Start a vm through manager")
    p_start.add_argument(metavar="<name>", dest="name", type=str, help="vm name")

    p_kill = action.add_parser("kill",
                               help="Forecefully stop a vm through manager")
    p_kill.add_argument(metavar="<name", dest="name", type=str, help="vm name")

    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

    args = parse_args()

    if args.action == "list":
        for v in vms2.list_vms():
            print(v)

    elif args.action == "create":
        disk_size = vms2.parse_size(args.disk_size) if args.disk_size else None
        vms2.create_vm(args.name, args.cores, vms2.parse_size(args.memory),
                       disk_size, args.encrypt_disk)

    elif args.action == "delete":
        vms2.delete_vm(args.name)

    elif args.action == "add-nic":
        vms2.add_nic(args.name, args.network)

    elif args.action == "clone":
        vms2.clone_vm(args.src_name, args.dst_name)

    elif args.action == "list-networks":
        for n,v in vms2.list_networks():
            print(f"{n}: (VLAN id {v})")


    elif args.action == 'list-running':
        print(f"{'Name':20s}Spice")
        for v in mgr_client.list_running():
            print(f"{v['name']:20s}{v['spice_port']} / {v['spice_password']}")

    elif args.action == 'start':
        mgr_client.start(args.name)
        print(f"VM `{args.name}' started.")

    elif args.action == 'kill':
        mgr_client.kill(args.name)
        print(f"VM `{args.name}' stopped forcefully.")

    else:
        raise NotImplementedError


if __name__ == '__main__':
    try:
        main()
        sys.exit(0)

    except vms2.VMS2Exception as exc:
        print("Error: %s" % exc)
        sys.exit(1)
