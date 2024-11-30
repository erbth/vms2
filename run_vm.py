#!/usr/bin/python3
import argparse
import logging
import signal
import sys
import vms2


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("name", metavar="<name>", type=str)

    parser.add_argument("--isoimg", type=str, help="ISO image to boot from")

    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

    # Ignore SIGINT and SIGTERM s.t. they are handled by the qemu process only
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    args = parse_args()
    vms2.run_vm(args.name, args.isoimg)


if __name__ == '__main__':
    try:
        main()
        sys.exit(0)

    except vms2.VMS2Exception as exc:
        print("Error: %s" % exc)
        sys.exit(1)
