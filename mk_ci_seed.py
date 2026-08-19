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
  -m OCT   new default octal value for permissions (start: 0640)
  -p       do copy ownership and permissions (default: False, use o,m)

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
files = {}
defperm = int("0640", base=8)

def usage():
    "Output usage instructions to stderr"
    print(__doc__, file=sys.stderr)

class injection:
    def __init__(self, unm, gnm, perm,
                 name="/tmp/dummy", content=""):
        self.owner = unm
        self.group = gnm
        self.permission = perm
        self.name = name
        self.content = content

def inject_file(fname, preserve=False, user="root", group="root", perm=defperm):
    "analyze fname and create injection object"
    # FIXME: Preprend '/' ?
    injname = fname.replace(':', '/')
    content = open(fname, "r").read().rstrip('\n')
    return injection(user, group, perm, injname, content) 

def file_injections(folders, preserve=False, user="root", group="root", perm=defperm):
    "Create dict with file injections from folder"
    pass

def yaml_injections(folders):
    "Create dict with yaml pieces from folder"
    # FIXME: Detect subdirectories and process (unless hidden)
    for folder in folders:
        for fnm in os.listdir(folder):
            dct = yaml.full_load_all(open(folder+'/'+fnm, 'r'))
            for doc in dct:
                #print(f" add {doc}")
                user_data.update(doc)

def key_injections(keys, replace=False):
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


def defaults():
    "Fill meta_data with defaults (generating random i_uuid nad hostname if needed)"
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
    # Defaults
    config_dirs = []
    inject_dirs = []
    uid = "root"
    gid = "root"
    mode = defperm
    # Process options
    parser = argparse.ArgumentParser(description="mk_ci_seed.py cloud-init ISO processor")
    parser.add_argument("isofile", help="The name of the ISO file to read/generate (mandatory).")
    parser.add_argument("-U", "--regenerate-uuid", action="store_true", help="Force UUID regeneration (default: False)")
    #parser.add_argument("-h", "--help", action="help", help="Help")
    parser.add_argument("-r", "--sshkey-overwrite", action="store_true",  help="Allow ssh keys to be replaced")
    parser.add_argument("-s", "--sshkey", action="append",  help="Add ssh keys (comma separated list)")
    parser.add_argument("-S", "--sshkey-reset", action="append",  help="Replaces ssh keys (comma separated list)")
    parser.add_argument("-c", "--config", action="append",  help="Add YAML snippets directory")
    parser.add_argument("-C", "--config-reset", action="append",  help="Replace user data with YAML snippets from directory")
    parser.add_argument("-i", "--inject", action="append",  help="Add Files to inject from directory tree")
    parser.add_argument("-I", "--inject-reset", action="append",  help="Replace files to inject from directory tree")
    parser.add_argument("-H", "--hostname", help="Set the hostname (default: read or randomly generated)")
    parser.add_argument("-o", "--owner", help="Set username:groupname (if preserve is not set), default root:root")
    parser.add_argument("-m", "--mode", help="Set acccess mode (octal value) to be used if preserve is not set, default 0640")
    parser.add_argument("-p", "--preserve", action="store_true", help="Copy owner and access mode from original file (default False)")
    args = parser.parse_args(argv[1:])
    #print(args)
    parse_iso(args.isofile)
    if args.hostname:
        hostame = args.hostname
    if args.regenerate_uuid:
        i_uuid = None
    if args.mode:
        mode = int(args.mode, 8)
    if args.owner:
        own = args.owner.split(':')
        uid = own[0]
        if len(own) >= 2:
            gid = own[1]
        if len(own) > 2:
            print(f"WARNING: Problems with parsing -o {args.owner}", file=sys.stderr)
    # SSH keys
    if args.sshkey_reset:
        sshkeys = [ key for it in args.sshkey_reset for key in it.split(",") ]
    if args.sshkey:
        sshkeys.extend([ key for it in args.sshkey for key in it.split(",") ])
    #print(sshkeys)
    # Files for injection
    if args.inject_reset:
        inject_dirs = [ dnm for it in args.inject_reset for dnm in it.split(",") ]
    if args.inject:
        inject_dirs.extend([ dnm for it in args.inject for dnm in it.split(",") ])
    #print(inject_dirs)
    # YAML config snippets
    if args.config_reset:
        config_dirs = [ dnm for it in args.config_reset for dnm in it.split(",") ]
    if args.config:
        config_dirs.extend([ dnm for it in args.config for dnm in it.split(",") ])
    #print(config_dirs)
    # Compose result
    defaults()
    key_injections(sshkeys, args.sshkey_overwrite)
    yaml_injections(config_dirs)
    file_injections(config_dirs, args.preserve, uid, gid, mode)
    print(meta_data)
    print(yaml.dump(user_data))


if __name__ == "__main__":
    main(sys.argv)
