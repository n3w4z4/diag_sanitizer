#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
key=anonymization.key
package='@socprime/logtotal-sanitizer'
usage() { echo "Usage: ./install.sh [--key-file PATH] [--version VERSION]"; }
while (($#)); do
  case "$1" in
    --key-file) key="${2:?Missing key path}"; shift 2;;
    --version) package="@socprime/logtotal-sanitizer@${2:?Missing version}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
for cmd in python3 node npm; do
  command -v "$cmd" >/dev/null || { echo "Missing prerequisite: $cmd" >&2; exit 1; }
done
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else "Python 3.10+ required")'
node -e 'if (+process.versions.node.split(".")[0] < 20) { console.error("Node.js 20+ required"); process.exit(1); }'
action=create
if [[ -e "$key" || -L "$key" ]]; then
  [[ -f "$key" && ! -L "$key" ]] || { echo 'Key must be a regular non-symlink file.' >&2; exit 1; }
  echo "An existing key was found: $key"
  echo 'Replacing it changes pseudonyms and breaks correlation with previous diagnostics.'
  read -r -p 'Continue installation using the existing key? [y/N] ' answer || exit 1
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]] || { echo 'Installation cancelled; key unchanged.'; exit 0; }
  action=keep
  read -r -p 'Generate a replacement key instead? [y/N] ' answer || exit 1
  if [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]; then
    read -r -p 'Type ROTATE to confirm replacement of the existing key: ' answer || exit 1
    [[ "$answer" == ROTATE ]] || { echo 'Installation cancelled; key unchanged.'; exit 0; }
    action=rotate
  fi
fi
python3 - "$key" "$action" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
if sys.argv[2] == 'keep' and not re.fullmatch(rb'[0-9a-fA-F]{64}', p.read_bytes().strip()):
    sys.exit('Existing key is invalid; expected 64 hexadecimal characters.')
if not p.parent.is_dir():
    sys.exit('Key parent directory does not exist.')
PY
# Local installation avoids sudo and global npm permissions.
npm install --prefix . --no-audit --no-fund --save-exact "$package"
cli=./node_modules/.bin/logtotal-sanitize
"$cli" --help >/dev/null
# Only touch key material after the dependency installation succeeds.
python3 - "$key" "$action" <<'PY'
import os, pathlib, re, secrets, sys, tempfile
p = pathlib.Path(sys.argv[1]); action = sys.argv[2]
if action == 'keep':
    if p.is_symlink() or not re.fullmatch(rb'[0-9a-fA-F]{64}', p.read_bytes().strip()):
        sys.exit('Existing key changed or is invalid.')
    p.chmod(0o600)
else:
    fd, name = tempfile.mkstemp(prefix='.key-', dir=p.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_hex(32))
            f.flush(); os.fsync(f.fileno())
        if action == 'create':
            os.link(name, p)  # Never overwrite a key created concurrently.
        else:
            if p.is_symlink() or not p.is_file():
                sys.exit('Existing key is no longer a regular file.')
            os.replace(name, p)
        print('Key generated.' if action == 'create' else 'Key replaced.')
    finally:
        pathlib.Path(name).unlink(missing_ok=True)
PY
if ! command -v ansible-inventory >/dev/null; then
  echo 'Optional: install Ansible for native inventory discovery, or use --inventory-json.'
fi
echo 'Installation complete. Use the local CLI with --cli ./node_modules/.bin/logtotal-sanitize'
printf 'Key path: %s\n' "$key"
