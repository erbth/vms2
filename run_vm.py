#!/usr/bin/python3
import argparse
import logging
import sys
import vms2


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", metavar="<name>", type=str)
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

    args = parse_args()
    vms2.run_vm(args.name)


if __name__ == '__main__':
    try:
        main()
        sys.exit(0)

    except vms2.VMS2Exception as exc:
        print("Error: %s" % exc)
        sys.exit(1)
