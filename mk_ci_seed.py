#!/usr/bin/env python3
"""mk_ci_seed.py [options] output.iso
 assembles an ISO file that can be used as meta-data source to seed cloud-init.
 If the ISO file already exists, it will be parsed and its settings be used
 as defaults.
Options -c/-i/-s can be specified multiple times.
Options:
  -c DIR:  directory with yaml snippets to be merged
  -C DIR:  dito, but reset list
  -i DIR:  directory with files to be injected
            Note: ':' will be replaced by '/', for ownership and permissions
            see options -o and -p
  -I DIR:  dito, but reset list
  -H NM:   hostname to be passed
  -s KEYS: comma-separated list of SSH keyfile to add (use PUBLIC keys!)
  -S KEYS: dito, but reset list
  -r       OK to overwrite ssh keys
  -U       regenerate UUID
  -o U:G   new default for user and group for file injection
            we start with root:root
  -p OCT   new default for permissions (start: 0640)

(c) Kurt Garloff <kurt@garloff.de>, 8/2026
SPDX-License-Identifier: CC-BY-SA-4.0
"""

import os
import sys
import yaml
import argparse

# globals
meta_data = {}
user_data = {}
i_uuid = None
hostname = None
sshkeys = []
user = "root"
group = "root"
perm = int("0640", base=8)
files = {}

class injection:
    def __init__(self, unm="root", gnm="root", perm=int("0640", base=8),
                 name="/tmp/dummy", content=""):
        self.owner = unm
        self.group = gnm
        self.permission = perm
        self.name = name
        self.content = content

def inject_file(fname):
    "analyze fname and create injection object"
    injname = fname.replace(':', '/')
    content = open(fname, "r").readlines()
    return injection(user, group, perm, injname, content) 

def usage():
    "Output usage instructions to stderr"
    print(__doc__, file=sys.stderr)

def file_injections(folder):
    "Create dict with file injections from folder"
    pass

def collect_yaml(folder):
    "Create dict with yaml pieces from folder"
    pass

def defaults():
    "Create dict with defaults"
    import secrets, base64, uuid
    global meta_data, i_uuid, hostname
    if not i_uuid:
        i_uuid = str(uuid.uuid4())
    if not hostname:
        hostname = f"host-{i_uuid[:8]}"
    meta_data["uuid"] = i_uuid
    meta_data["hostname"] = hostname
    idx = hostname.find('.')
    if idx == -1:
        meta_data["name"] = hostname
    else:
        meta_data["name"] = hostname[0:idx]
    meta_data["random_seed"] = base64.b64encode(secrets.token_bytes(512)).decode()

def inject_keys(keys, replace=False):
    import os.path
    global meta_data
    meta_data["public_keys"] = {}
    meta_data["keys"] = []
    for key in keys:
        knm = None
        keycontent = open(key, "r").read().rstrip('\n')
        # Protect against accidentially injecting PRIVATE keys
        if keycontent.startswith("-----BEGIN RSA PRIVATE KEY-----"):
            print(f"ERROR: Reject private key {key} for injection", file=sys.stderr)
            sys.exit(2)
        idx = keycontent.rfind(" ")
        if idx != -1:
            knm = keycontent[idx+1:]
            if knm == "Generated-by-Nova":
                knm = None
        if not knm:
            knm = os.path.basename(key).rstrip(".pub").rstrip(".pem")
        if knm in meta_data["public_keys"]:
            # Specifying the same key multiple times produces a warning, overwriting an error
            if (keycontent == meta_data["public_keys"][knm]):
                print(f"WARNING: Key {knm} in {key} specified multiple times", file=sys.stderr)
            else:
                if replace:
                    err = "WARNING"
                    spc = "  ->   "
                else:
                    err = "ERROR"
                    spc = "  -> "
                print(f"{err}: Key {knm} already exists, replace with {key}", file=sys.stderr)
                print(f"{err}: {meta_data['public_keys'][knm]}\n{spc}  {keycontent}", file=sys.stderr)
                if not replace:
                    sys.exit(3)
        meta_data["public_keys"][knm] = keycontent
        meta_data["keys"].append({"name": knm, "type": "ssh", "data": keycontent})


def make_iso(outputfile):
    "Create cloud-config file into outputfile"
    pass

def parse_iso(outputfile):
    "Read ISO and parse settings"
    global meta_data, user_data, i_uuid, hostname, sshkeys, files

def main(argv):
    "Entrypoint"
    global i_uuid, hostname, sshkeys, files
    if len(argv) < 2:
        usage()
        sys.exit(1)
    # Process options
    parser = argparse.ArgumentParser(description="mk_ci_seed.py cloud-init ISO generator")
    parser.add_argument("isofile", help="The name of the ISO file to read/generate (mandatory).")
    parser.add_argument("-U", "--regenerate-uuid", action="store_true", help="Force UUID regeneration")
    #parser.add_argument("-h", "--help", action="help", help="Help")
    parser.add_argument("-r", "--sshkey-overwrite", action="store_true",  help="Allow ssh keys to be replaced")
    parser.add_argument("-s", "--sshkey", action="append",  help="Add ssh keys (comma separated list)")
    parser.add_argument("-S", "--sshkey-reset", action="append",  help="Replaces ssh keys (comma separated list)")
    parser.add_argument("-H", "--hostname",  help="Set the hostname")
    args = parser.parse_args(argv[1:])
    print(args)
    parse_iso(args.isofile)
    if args.regenerate_uuid:
        i_uuid = None
    if args.sshkey_reset:
        sshkeys = [ key for it in args.sshkey_reset for key in it.split(",") ]
    if args.sshkey:
        sshkeys.extend([ key for it in args.sshkey for key in it.split(",") ])
    print(sshkeys)
    if args.hostname:
        hostame = args.hostname
    defaults()
    inject_keys(sshkeys, args.sshkey_overwrite)
    print(meta_data)


if __name__ == "__main__":
    main(sys.argv)
