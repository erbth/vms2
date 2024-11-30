#!/usr/bin/python3
import argparse
import logging
import sys
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
    p_create.add_argument(metavar="<disk size>", dest="disk_size", type=str)
    p_create.add_argument("--encrypt-disk", metavar="<key id>", type=str)

    p_delete = action.add_parser("delete", help="Delete vm")
    p_delete.add_argument(metavar="<name>", dest="name", type=str)

    p_add_nic = action.add_parser("add-nic", help="Add network interface")
    p_add_nic.add_argument(metavar="<name>", dest="name", type=str, help="VM name")
    p_add_nic.add_argument(metavar="<network>", dest="network", type=str)

    p_clone = action.add_parser("clone", help="Clone a vm")
    p_clone.add_argument(metavar="<src name>", dest="src_name", type=str)
    p_clone.add_argument(metavar="<dst name>", dest="dst_name", type=str)

    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

    args = parse_args()

    if args.action == "list":
        for v in vms2.list_vms():
            print(v)

    elif args.action == "create":
        vms2.create_vm(args.name, args.cores, vms2.parse_size(args.memory),
                       vms2.parse_size(args.disk_size), args.encrypt_disk)

    elif args.action == "delete":
        vms2.delete_vm(args.name)

    elif args.action == "add-nic":
        vms2.add_nic(args.name, args.network)


    else:
        raise NotImplementedError


if __name__ == '__main__':
    try:
        main()
        sys.exit(0)

    except vms2.VMS2Exception as exc:
        print("Error: %s" % exc)
        sys.exit(1)
