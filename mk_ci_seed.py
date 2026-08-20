#!/usr/bin/env python3
"""mk_ci_seed.py [options] output.iso
 assembles an ISO file that can be used as meta-data source to seed cloud-init.
 If the ISO file already exists, it will be parsed and its settings be used
 as defaults.
Options -c/-i/-s can be specified multiple times.
Options:
  -c DIR   directory with yaml snippets to be merged (comma-separated)
  -C DIR   dito, but reset list
  -i DIR   directory with files to be injected
            Note: ':' will be replaced by '/', for ownership and permissions
            see options -o and -p
  -I DIR   dito, but reset list
  -o U:G   new default for user and group for file injection
            we start with root:root
  -m OCT   new default octal value for permissions (start: 0640)
  -p       do copy ownership and permissions (default: False, use o,m)
  -P       do copy permissions (default: False, but not ownership)
  -s KEYS  comma-separated list of SSH keyfile to add (use PUBLIC keys!)
  -S KEYS  dito, but reset list
  -r       OK to overwrite ssh keys
  -U       regenerate UUID
  -H NM    hostname to be passed

(c) Kurt Garloff <kurt@garloff.de>, 8/2026
SPDX-License-Identifier: CC-BY-SA-4.0
"""

import os
import os.path
import sys
import pwd
import grp
import secrets
import base64
import gzip
import uuid
import json
import argparse
import tempfile
import subprocess
import yaml

# globals
meta_data = {}
user_data = {}
i_uuid = None
hostname = None
sshkeys = []
files = {}
defperm = 0o640
debug = False


def usage():
    "Output usage instructions to stderr, somewhat duplicated with argparse --help"
    print(__doc__, file=sys.stderr)


def debug_print(*args, **kwa):
    "Wrapper for print only if debug is set"
    if debug:
        print(*args, **kwa)


# Configuration
MAX_PLAIN_SIZE = 1024 * 10  # 10KB: Files larger than this get gzipped
# Characters we allow in a "plain" YAML string without fear of injection issues
ALLOWED_WHITESPACE = {'\n', '\r', '\t'}


def encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def encode_gzip_b64(data: bytes) -> str:
    return base64.b64encode(gzip.compress(data)).decode('utf-8')


def is_text_safe(text: str) -> bool:
    """
    Checks if the string is composed of printable characters.
    This prevents injecting control characters that break YAML or Shells.
    """
    for char in text:
        if not char.isprintable() and char not in ALLOWED_WHITESPACE:
            return False
    return True


def process_file_for_yaml(filepath: str):
    """
    Determines the best way to represent a file for YAML injection.
    Returns a tuple: (representation_type, content)
    """
    file_size = os.path.getsize(filepath)

    # Case 1: Large files (Gzip + B64)
    if file_size > MAX_PLAIN_SIZE:
        with open(filepath, 'rb') as f:
            return "gzip_b64", encode_gzip_b64(f.read())

    # Read as bytes for inspection
    with open(filepath, 'rb') as f:
        raw_data = f.read()

    # Case 2: Try to see if it is valid UTF-8 text
    try:
        text_content = raw_data.decode('utf-8')

        # Case 2a: It is text, but is it "safe" (no control chars)?
        if is_text_safe(text_content):
            return "text/plain", text_content  # .rstrip('\n')
        else:
            # Case 2b: It is text, but has "weird" characters (e.g. \x01)
            return "b64", encode_b64(raw_data)

    except UnicodeDecodeError:
        # Case 3: It's binary (cannot be decoded as UTF-8)
        return "b64", encode_b64(raw_data)


class Injection:
    "Data structure for file injections"
    def __init__(self, unm, gnm, perm, name="/tmp/dummy",
                 content="", enc="text/plain"):
        self.owner = unm
        self.group = gnm
        self.permissions = perm
        self.name = name
        self.content = content
        self.encoding = enc

    def fields(self) -> dict:
        return {"path": self.name, "content": self.content,
                "owner": self.owner+":"+self.group,
                "permissions": oct(self.permissions),
                "encoding": self.encoding}

    def __repr__(self):
        return str(self.fields())


def inject_file(fname, preserve=False, keepperm=False, user="root", group="root", perm=defperm, iname=''):
    "analyze fname and create injection object"
    injname = iname.replace(':', '/')
    enc, content = process_file_for_yaml(fname)
    if preserve or keepperm:
        st = os.stat(fname)
        if preserve:
            user  = pwd.getpwuid(st.st_uid).pw_name
            group = grp.getgrgid(st.st_gid).gw_name
        return Injection(user, group, st.st_mode & 0o7777, injname, content, enc)
    return Injection(user, group, perm, injname, content, enc)


def file_injections(folder, preserve=False, keepperm=False, user="root", group="root", perm=defperm, prefix=''):
    "Create dict with file injections from folder"
    global files
    with os.scandir(folder) as it:
        for fnm in it:
            if fnm.name.startswith('.'):
                continue
            fullnm = folder+'/'+fnm.name
            pnm = prefix+'/'+fnm.name
            if fnm.is_dir():
                return file_injections(fullnm, preserve, keepperm, user, group, perm, pnm)
            if fnm.is_file():
                inj = inject_file(fullnm, preserve, keepperm, user, group, perm, pnm)
                files[inj.name] = inj
    return None


def append_or_replace(path, inj, udata):
    "Append inj to udata if not in there yet, otherwise update"
    for wf in udata:
        if wf["path"] == path:
            if wf.get("content") != inj.content:
                print(f"WARNING: write_files {path} replaced with {inj.content}")
            else:
                debug_print(f"INFO: write_files {path} found with identical content {inj.fields()}")
            # wf = inj.fields()
            for key, val in inj.fields().items():
                wf[key] = val
            return
    udata.append(inj.fields())


def apply_file_injections(ifiles):
    "Add injected files to user_data"
    global user_data
    if not ifiles:
        return
    if "write_files" not in user_data:
        user_data["write_files"] = []
    for key, ifile in ifiles.items():
        # Avoid duplication
        append_or_replace(key, ifile, user_data["write_files"])


def yaml_injections(folder):
    "Create dict with yaml pieces from folder"
    with os.scandir(folder) as it:
        for fnm in it:
            # Ignore hidden files / subdirectories
            if fnm.name.startswith('.'):
                continue
            fullnm = folder+'/'+fnm.name
            if fnm.is_dir():
                return yaml_injections(fullnm)
            if fnm.is_file():
                dct = yaml.full_load_all(open(fullnm, 'r', encoding="utf-8"))
                for doc in dct:
                    debug_print(f" add {doc}")
                    user_data.update(doc)
    return None


def key_injections(keys, replace=False):
    "Collect ssh keys to be injected"
    global meta_data
    meta_data["public_keys"] = {}
    meta_data["keys"] = []
    for key in keys:
        knm = None
        # Special case: When we extract keys from existing ISO, we don't have a file
        if key.startswith("<<</"):
            idx = key.find("\n")
            if idx == -1:
                print(f"ERROR: Illegal key content {key}", file=sys.stderr)
                sys.exit(4)
            keycontent = key[idx+1:]
        else:
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
                    # Overwrite
                    for k in meta_data["keys"]:
                        if k["name"] == knm:
                            k["type"] = "ssh"  # likely unchanged ...
                            k["data"] = keycontent
                            break
                else:
                    err = "ERROR"
                    spc = "  -> "
                print(f"{err}: Key {knm} already exists, replace with {key}", file=sys.stderr)
                print(f"{err}: {meta_data['public_keys'][knm]}\n{spc}  {keycontent}", file=sys.stderr)
                if not replace:
                    sys.exit(3)
        else:
            meta_data["keys"].append({"name": knm, "type": "ssh", "data": keycontent})
        meta_data["public_keys"][knm] = keycontent


def defaults():
    "Fill meta_data with defaults (generating random i_uuid nad hostname if needed)"
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


# LLM helped ...
class MultiLineDumper(yaml.SafeDumper):
    pass


def str_representer(dumper, data):
    "Prefer literal block style for strings"
    if '\n' in data:
        # Use '|' for literal block style
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


# Register the representer with our custom Dumper
MultiLineDumper.add_representer(str, str_representer)


def run_command(cmd):
    "capture_stdout is not available in old py3, so use PIPE"
    # universal_newlines=True ensures we get strings instead of bytes.
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, check=False)
    rc = result.returncode

    if rc != 0:
        print(f"ERROR: {cmd} failed with exit code {rc}", file=sys.stderr)
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)

    return result


def make_iso(outputfile):
    "Create cloud-config file into outputfile"
    tdir = tempfile.mkdtemp(suffix=".dir", dir=os.path.dirname(outputfile))
    lpath = tdir + "/openstack/latest/"
    os.makedirs(lpath)
    with open(lpath+"meta_data.json", "w", encoding="utf-8") as out:
        json.dump(meta_data, out)
    with open(lpath+"user_data", "w", encoding="utf-8") as out:
        print("#cloud-config", file=out)
        yaml.dump(user_data, out, Dumper=MultiLineDumper, sort_keys=False)
    # mkisofs -o $outputfile -preparer mk_seed_ci.py -V config-2 -J -R $tdir >/dev/null 2>&1
    ret = run_command(["mkisofs", "-o", outputfile, "-preparer", "mk_seed_ci.py",
                      "-V", "config-2", "-R", tdir])
    # Clean up
    # shutil.rmtree(tdir)
    os.remove(lpath+"user_data")
    os.remove(lpath+"meta_data.json")
    os.rmdir(lpath)
    os.rmdir(tdir+"/openstack")
    os.rmdir(tdir)
    if ret.returncode:
        sys.exit(ret.returncode)


def parse_iso(outputfile):
    "Read ISO and parse settings"
    global meta_data, user_data, i_uuid, hostname, sshkeys, files
    if not os.access(outputfile, os.R_OK):
        return
    # isoinfo -R -i $outputfile -x /openstack/latest/meta_data.json
    ret = run_command(["isoinfo", "-R", "-i", outputfile, "-x", "/openstack/latest/meta_data.json"])
    if ret.returncode:
        sys.exit(ret.returncode)
    meta_data = json.loads(ret.stdout)
    # Extract hostname, UUID
    if "hostname" in meta_data:
        hostname = meta_data["hostname"]
    if "uuid" in meta_data:
        i_uuid = meta_data["uuid"]
    # ssh_keys
    if "public_keys" in meta_data:
        for knm, kcont in meta_data["public_keys"].items():
            sshkeys.append(f"<<</{knm}.pub\n{kcont}")
    ret = run_command(["isoinfo", "-R", "-i", outputfile, "-x", "/openstack/latest/user_data"])
    if ret.returncode:
        sys.exit(ret.returncode)
    user_data = yaml.safe_load(ret.stdout)
    # Extract write_files
    if "write_files" in user_data:
        for ifile in user_data["write_files"]:
            user, group = ifile["owner"].split(":")
            perm = ifile.get("permissions")
            if perm:
                perm = int(perm, 8)
            else:
                perm = defperm
            path = ifile["path"]
            enc = ifile.get("encoding") or "text/plain"
            files[path] = Injection(user, group, perm, ifile["path"],
                                    ifile.get("content"), enc)


def main(argv):
    "Entrypoint"
    global i_uuid, hostname, sshkeys, debug
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
    parser = argparse.ArgumentParser(description="""mk_ci_seed.py cloud-init ISO processor.
It will read the ISO file if it exists and parse it,
defaults will be used otherwise.  Options -s, -c, -i can be used multiple times,
but they also accept comma-separated lists.""", epilog="""(c) Kurt Garloff <kurt@garloff.de>, 8/2026
SPDX-License-Identifier: CC-BY-SA-4.0""", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("isofile", help="The name of the ISO file to read/generate (mandatory).")
    parser.add_argument("-r", "--sshkey-overwrite", action="store_true", help="Allow ssh keys to be replaced")
    parser.add_argument("-s", "--sshkey", action="append", help="Add ssh keys (comma separated list)")
    parser.add_argument("-S", "--sshkey-reset", action="append", help="Replaces ssh keys (comma separated list)")
    parser.add_argument("-c", "--config", action="append", help="Add YAML snippets directory")
    parser.add_argument("-C", "--config-reset", action="append", help="Replace user data with YAML snippets from directory")
    parser.add_argument("-i", "--inject", action="append", help="Add Files to inject from directory tree")
    parser.add_argument("-I", "--inject-reset", action="append", help="Replace files to inject from directory tree")
    parser.add_argument("-o", "--owner", help="Set username:groupname (if preserve is not set), default root:root")
    parser.add_argument("-m", "--mode", help="Set acccess mode (octal value) to be used if preserve is not set, default 0640")
    parser.add_argument("-p", "--preserve", action="store_true", help="Copy owner and access mode from original file (default False)")
    parser.add_argument("-P", "--permissions", action="store_true", help="Copy access mode from original file but not ownership (default False)")
    parser.add_argument("-U", "--regenerate-uuid", action="store_true", help="Force UUID regeneration (default: False)")
    parser.add_argument("-H", "--hostname", help="Set the hostname (default: read or randomly generated)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enabled debugging output (default: False)")
    args = parser.parse_args(argv[1:])
    if args.debug:
        debug = True
    debug_print(args)
    parse_iso(args.isofile)
    if args.hostname:
        hostname = args.hostname
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
        sshkeys = [key for it in args.sshkey_reset for key in it.split(",")]
    if args.sshkey:
        sshkeys.extend([key for it in args.sshkey for key in it.split(",")])
    debug_print(sshkeys)
    # Files for injection
    if args.inject_reset:
        inject_dirs = [dnm for it in args.inject_reset for dnm in it.split(",")]
    if args.inject:
        inject_dirs.extend([dnm for it in args.inject for dnm in it.split(",")])
    debug_print(inject_dirs)
    # YAML config snippets
    if args.config_reset:
        config_dirs = [dnm for it in args.config_reset for dnm in it.split(",")]
    if args.config:
        config_dirs.extend([dnm for it in args.config for dnm in it.split(",")])
    debug_print(config_dirs)
    # Compose result
    defaults()
    key_injections(sshkeys, args.sshkey_overwrite)
    for cdir in config_dirs:
        yaml_injections(cdir)
    for fdir in inject_dirs:
        file_injections(fdir, args.preserve, args.permissions, uid, gid, mode)
    debug_print(meta_data)
    debug_print(files)
    apply_file_injections(files)
    debug_print('#cloud-config')
    debug_print(yaml.dump(user_data, Dumper=MultiLineDumper, sort_keys=False))
    make_iso(args.isofile)
    debug_print(f"Pass a cdrom (scsi-cd) device named cidata with backing file {args.isofile} to qemu ...")


if __name__ == "__main__":
    main(sys.argv)
