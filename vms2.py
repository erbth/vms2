"""
Library
"""
from contextlib import contextmanager
import json
import logging
import math
import os
import re
import secrets
import shutil
import socket
import subprocess
import uuid

CEPH_ID = "vmm"
CEPH_CONFFILE = "/etc/ceph/vmm.conf"
CEPH_FSNAME = "cephfs"
CEPHFS_BASE = "/vms2"
RBD_POOL = "vms2"
CEPHFS_MOUNTPOINT = "/srv/vms2/desc_fs"

MAC_RANGE = "52:55:00:XX:XX:XX"

VM_DIR = os.path.join(CEPHFS_MOUNTPOINT, "vms")
FW_DIR = os.path.join(CEPHFS_MOUNTPOINT, "fw")
STATE_FILE = os.path.join(CEPHFS_MOUNTPOINT, "config", "state.json")

SPICE_PORT_DIR = '/tmp/vms2/spice_ports'
SPICE_PORT_MIN = 52000
SPICE_PORT_MAX = 52999

ENCRYPT_SECRET_FILE_DIR = "/srv/vms2/disk_secrets"


logger = logging.getLogger("vms2")


NETWORK_VLAN_MAP = {
    "default":      1,
    "local":        30,
    "transport":    99,
    "matrix":       100,
    "siteA":        120,
    "siteB":        121,
    "tsl_runtime":  200,
    "mpip4":        300
}


# Actions
def list_vms():
    _ensure_mounted()
    return sorted(os.listdir(VM_DIR))


def create_vm(name, cores, memory, disk_size, disk_encrypt_key_id=None):
    _ensure_mounted()
    _check_name(name)
    _check_cores(cores)
    _check_memory(memory)
    _check_disk_size(disk_size)

    if disk_encrypt_key_id is not None:
        _check_secret_key_id(disk_encrypt_key_id)

    if name in os.listdir(VM_DIR):
        raise VMExists(name)

    # Create directory
    vmdir = os.path.join(VM_DIR, name)
    os.mkdir(vmdir, 0o755)

    # Create config file
    cfg = {
        'name': name,
        'platform': 'pc-i440fx-3.1',
        'cores': cores,
        'memory': memory,
        'fwmode': 'uefi',
        'nics': [],
        'disks': [{
            'type': 'rbd',
            'image': name,
            'encrypt_key_id': disk_encrypt_key_id
        }]
    }

    with open(os.path.join(vmdir, 'config.json'), 'w') as f:
        f.write(json.dumps(cfg, indent=4) + '\n')

    # Create rbd image for disk
    _create_rbd_image(name, disk_size, encrypt=disk_encrypt_key_id)

    # Copy nvram.flash
    shutil.copyfile(
            os.path.join(FW_DIR, 'OVMF_VARS.fd'),
            os.path.join(vmdir, 'nvram.flash'))


def delete_vm(name):
    _ensure_mounted()
    _ensure_exists(name)

    # Lock
    _lock(name)

    # Remove rbd image
    _delete_rbd_image(name)

    # Remove directory
    shutil.rmtree(os.path.join(VM_DIR, name))


def add_nic(name, network):
    _ensure_mounted()
    _ensure_exists(name)
    _check_network(network)

    with _locked(name):
        cfg_file = os.path.join(VM_DIR, name, 'config.json')

        # Read config
        with open(cfg_file, 'r') as f:
            cfg = json.loads(f.read().strip())

        # Find free MAC
        state = _read_state()
        cfg['nics'].append({
            'mac': state['next_mac'],
            'type': 'bridge',
            'network': network
        })

        state['next_mac'] = _inc_mac(state['next_mac'], MAC_RANGE)

        # Write config
        with open(cfg_file, 'w') as f:
            f.write(json.dumps(cfg, indent=4) + '\n')

        # Update state
        _write_state(state)


def clone_vm(src_name, dst_name):
    _ensure_mounted()
    _check_name(src_name)
    _check_name(dst_name)
    _ensure_exists(src_name)

    if dst_name in os.listdir(VM_DIR):
        raise VMExists(dst_name)

    with _locked(src_name):
        # Create directory
        vmdir = os.path.join(VM_DIR, dst_name)
        os.mkdir(vmdir, 0o755)

        src_cfg = _read_vm_config(src_name)

        # Create config file
        cfg = {}
        for k in ['name', 'platform', 'cores', 'memory', 'fwmode']:
            cfg[k] = src_cfg[k]

        disks = []
        disks_to_clone = []
        for d in src_cfg['disks']:
            if d['type'] != 'rbd':
                raise VMS2Exception("Unsupported disk type")

            src_image = d['image']
            if src_name not in src_image:
                raise VMS2Exception("Disk without src vm name")

            dst_image = src_image.replace(src_name, dst_name)

            disks.append({
                'type': 'rbd',
                'image': dst_image,
                'encrypt_key_id': d['encrypt_key_id']
            })

            disks_to_clone.append((src_image, dst_image))

        cfg['disks'] = disks

        nics = []
        cfg['nics'] = nics

        with open(os.path.join(vmdir, 'config.json'), 'w') as f:
            f.write(json.dumps(cfg, indent=4) + '\n')

        # Clone rbd images
        for src,dst in disks_to_clone:
            _clone_rbd_image(src, dst)

        # Copy nvram.flash
        shutil.copyfile(
                os.path.join(VM_DIR, src_name, 'nvram.flash'),
                os.path.join(vmdir, 'nvram.flash'))


def run_vm(name, iso_img=None):
    _ensure_mounted()
    _ensure_exists(name)
    with _locked(name):
        vmdir = os.path.join(VM_DIR, name)
        cfg = _read_vm_config(name)

        env = {}

        if cfg['fwmode'] != 'uefi':
            raise VMS2Exception("Non-UEFI vms are not supported yet")

        disks = []
        for i,d in enumerate(cfg['disks']):
            if d['type'] == 'rbd':
                enc_opts = ""
                enc_args = []

                if (key_id:=d['encrypt_key_id']) is not None:
                    _check_secret_key_id(key_id)
                    enc_opts = ",encrypt.format=luks2,encrypt.key-secret=disk%d" % i
                    enc_args = [
                            '-object',
                            'secret,id=disk%d,file=%s,format=raw' %
                                (i, _determine_encrypt_secret_file(key_id))
                    ]

                # See https://ceph.io/en/news/blog/2022/qemu-kvm-tuning/
                disks += [
                        '-drive', 'format=rbd,id=disk%d,file=rbd:vms2/%s:conf=%s:id=%s,if=none,cache=none%s' %
                            (i, d['image'], CEPH_CONFFILE, CEPH_ID, enc_opts),
                        '-device', 'virtio-blk-pci,drive=disk%d' % i,
                        *enc_args
                ]

            else:
                raise VMS2Exception("Unsupported disk type")

        with _get_free_spice_port() as spice_port:
            nics = []
            brdesc = []
            for i,n in enumerate(cfg['nics']):
                if n['type'] == 'bridge':
                    # Interface names must be unique
                    ifname = 'tap_%d_%d' % (spice_port, i)
                    script = os.path.join(os.path.dirname(__name__), 'qemu-tap-ifup.py')
                    nics += ['-netdev', 'tap,id=nic%d,ifname=%s,script=%s,downscript=no' % (i, ifname, script)]
                    brdesc.append('%s.%s.%d' % (ifname, n['mac'], NETWORK_VLAN_MAP[n['network']]))

                elif n['type'] == 'l2tpv3':
                    nics += ['-netdev', ('l2tpv3,id=nic%d,src=%s,dst=%s,'
                                'txsession=%s,rxsession=%s,udp=on,srcport=%d,dstport=%d') %
                                (i, n['local'][0], n['remote'][0],
                                 n['txsession'], n['rxsession'], n['local'][1], n['remote'][1])]

                else:
                    raise VMS2Exception("Unsupported nic type")

                nics += ['-device', 'virtio-net,netdev=nic%d,mac=%s' % (i, n['mac'])]

            if brdesc:
                env['VMS2_BR_IFUP_DESC'] = '-'.join(brdesc)

            iso_args = []
            if iso_img is not None:
                print("Booting from ISO image `%s'." % iso_img)
                iso_args = ['-cdrom', iso_img, '-boot', 'd']


            spice_password = _generate_spice_password()

            print("spice_port:     %s" % spice_port)
            print("spice_password: %s" % spice_password, flush=True)

            ret = subprocess.run([
                'kvm',
                '-name', cfg['name'],
                '-M', cfg['platform'],
                '-cpu', 'host', '-smp', 'cpus=%d,cores=%d' % (cfg['cores'], cfg['cores']),
                '-m', 'size=%dB' % cfg['memory'],
                '-drive', 'if=pflash,format=raw,readonly=on,file=%s' % os.path.join(FW_DIR, 'OVMF_CODE.fd'),
                '-drive', 'if=pflash,format=raw,file=%s' % os.path.join(vmdir, 'nvram.flash'),
                *disks,
                *nics,
                '-vga', 'qxl', '-spice', 'port=%d,password-secret=spice' % spice_port,
                # This is not more secure than passing the password directly,
                # but silences the warning...
                '-object', 'secret,id=spice,data=%s,format=raw' % spice_password,
                '-global', 'PIIX4_PM.disable_s3=0',
                *iso_args
            ],
            env=env)

            if ret.returncode != 0:
                raise VMS2Exception("Failed to run vm")


# Internal functions
def _ensure_mounted():
    """
    Mount cephfs if required
    """
    _ensure_dir(CEPHFS_MOUNTPOINT)

    if not os.path.ismount(CEPHFS_MOUNTPOINT):
        ret = subprocess.run([
            'mount', '-t', 'ceph',
            '%s@.%s=%s' % (CEPH_ID, CEPH_FSNAME, CEPHFS_BASE),
            CEPHFS_MOUNTPOINT,
            "-oconf=%s," % CEPH_CONFFILE])

        if ret.returncode != 0:
            raise VMS2Exception("Failed to mount cephfs")


def _ensure_dir(d):
    comp = d.split('/')
    for i in range(len(comp)):
        path = '/'.join(comp[:i+1])
        if not path:
            continue

        if not os.path.exists(path):
            logger.info("Creating directory %s" % path)
            os.mkdir(path, 0o755)


def _ensure_exists(name):
    if name not in os.listdir(VM_DIR):
        raise NoSuchVM(name)


def _inc_mac(mac, pattern):
    val = int(mac.replace(':', ''), base=16)
    val += 1

    text = '%012x' % val
    mac = ':'.join(text[i*2:i*2+2] for i in range(6))

    for i in range(len(pattern)):
        if pattern[i] == 'X':
            continue

        if mac[i] != pattern[i].lower():
            raise VMS2Exception("next_mac overflow")

    return mac


def _lock(name):
    lock_token = socket.getfqdn() + '_' + str(uuid.uuid4())
    filename = os.path.join(os.path.join(VM_DIR, name, '.lock'))
    tmp_filename = filename + "_" + lock_token

    try:
        with open(tmp_filename, 'w') as f:
            f.write(lock_token)

        try:
            os.link(tmp_filename, filename)
        except FileExistsError as exc:
            raise VMS2Exception("VM locked") from exc

    finally:
        os.unlink(tmp_filename)

    return lock_token

def _unlock(name, lock_token):
    filename = os.path.join(os.path.join(VM_DIR, name, '.lock'))

    with open(filename, 'r') as f:
        c = f.read()

    if c != lock_token:
        raise VMS2Exception("VM not locked")

    os.unlink(filename)

@contextmanager
def _locked(name):
    token = _lock(name)
    try:
        yield
    finally:
        _unlock(name, token)


def _read_state():
    with open(STATE_FILE, 'r') as f:
        return json.loads(f.read().strip())

def _write_state(state):
    with open(STATE_FILE, 'w') as f:
        f.write(json.dumps(state, indent=4) + '\n')


def _read_vm_config(name):
    cfg_file = os.path.join(VM_DIR, name, 'config.json')

    # Read config
    with open(cfg_file, 'r') as f:
        return json.loads(f.read().strip())


def _create_rbd_image(name, size, encrypt=None):
    ret = subprocess.run([
        'rbd',
        '--id', CEPH_ID, '-c', CEPH_CONFFILE,
        'create',
        RBD_POOL + '/' + name,
        '--size', '%dM' % int(math.ceil(size / 1024**2)),
        '--no-progress'])

    if ret.returncode != 0:
        raise VMS2Exception("Failed to create rbd image")

    # Enable encrypt if specified
    if encrypt:
        logger.info("Encrypting image with key with id %s" % encrypt)
        key_file = _determine_encrypt_secret_file(encrypt)

        ret = subprocess.run([
            'rbd',
            '--id', CEPH_ID, '-c', CEPH_CONFFILE,
            'encryption', 'format',
            RBD_POOL + '/' + name, 'luks2', key_file])

        if ret.returncode != 0:
            raise VMS2Exception("Failed to format rbd image for encryption")

        ret = subprocess.run([
            'rbd',
            '--id', CEPH_ID, '-c', CEPH_CONFFILE,
            'resize',
            RBD_POOL + '/' + name,
            '--size', '%dM' % int(math.ceil(size / 1024**2)),
            '--encryption-passphrase-file', key_file,
            '--no-progress'])

        if ret.returncode != 0:
            raise VMS2Exception("Failed to resize image after formatting for encryption")


def _delete_rbd_image(name):
    print("Deleting RBD image:")
    ret = subprocess.run([
        'rbd',
        '--id', CEPH_ID, '-c', CEPH_CONFFILE,
        'remove',
        RBD_POOL + '/' + name])

    if ret.returncode != 0:
        raise VMS2Exception("Failed to delete rbd image")


def _clone_rbd_image(src_name, dst_name):
    raise NotImplementedError


def _generate_spice_password(length=20):
    """
    Generate a password for use with spice
    """
    return secrets.token_urlsafe(length)


def _determine_encrypt_secret_file(secret_name):
    return os.path.join(ENCRYPT_SECRET_FILE_DIR, secret_name)


@contextmanager
def _get_free_spice_port():
    """
    Allocate a free spice port and return it
    """
    os.makedirs(SPICE_PORT_DIR, mode=0o755, exist_ok=True)
    for port in range(SPICE_PORT_MIN, SPICE_PORT_MAX + 1):
        path = os.path.join(SPICE_PORT_DIR, str(port))

        try:
            fd = os.open(path, flags=os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode=0o644)
            os.close(fd)
            found = True
            break

        except FileExistsError:
            pass

    if not found:
        raise VMS2Exception("No free SPICE port available")

    try:
        yield port
    finally:
        os.unlink(path)


# Validating input
def _check_name(name):
    if not re.fullmatch(r'[0-9a-zA-Z_.-]+', name):
        raise VMS2Exception("Invalid vm name")

def _check_secret_key_id(id_):
    if not re.fullmatch(r'[0-9a-zA-Z_.-]+', id_):
        raise VMS2Exception("Invalid secret key id")

def _check_cores(cores):
    if cores < 1 or cores > 256:
        raise VMS2Exception("Invalid core count")

def _check_memory(memory):
    if memory < 1 or memory > 1024**4:
        raise VMS2Exception("Invalid memory size")

def _check_disk_size(size):
    if size < 1:
        raise VMS2Exception("Invalid disk size")

def _check_network(name):
    if name not in NETWORK_VLAN_MAP:
        raise VMS2Exception("Invalid network")


# Utility functions
def parse_size(s):
    """
    Parse a size represented as xxx[PB...] into bytes. IEC conversion is used.

    :type s: str
    """
    m = re.fullmatch(r'(\d+)([PpTtGgMmKk])', s)
    if not m:
        raise VMS2Exception("Invalid size specification: %s" % s)

    mult = {
            'p': 1024**5,
            't': 1024**4,
            'g': 1024**3,
            'm': 1024**2,
            'k': 1024
    }

    return int(m[1]) * mult[m[2].lower()]


# Exceptions
class VMS2Exception(RuntimeError):
    pass


class NoSuchVM(VMS2Exception):
    def __init__(self, vm_name):
        super().__init__("No such VM: %s" % vm_name)


class VMExists(VMS2Exception):
    def __init__(self, vm_name):
        super().__init__("VM exists already: %s" % vm_name)
