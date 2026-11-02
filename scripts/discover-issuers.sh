#!/usr/bin/env bash
# Scan a directory of operator-supplied CA cert/key pairs, keep only the ones
# OpenSSL confirms are usable to sign TLS server certs, stage them into the
# config's ca_dir, and switch config.toml to directory issuer mode.
#
# Usage: discover-issuers.sh <source_dir> [config.toml] [ca_dir]
#
#   source_dir   directory containing candidate <stem>.pem/<stem>.key pairs
#   config.toml  defaults to ./config.toml
#   ca_dir       defaults to the directory next to config.toml named
#                issuer/cas, or the ca_dir already set in config.toml
set -euo pipefail

source_dir=${1:?usage: discover-issuers.sh <source_dir> [config.toml] [ca_dir]}
config=${2:-config.toml}
source_dir=${source_dir%/}

for bin in openssl rg; do
    command -v "$bin" >/dev/null || { echo "missing required tool: $bin" >&2; exit 1; }
done
[[ -d "$source_dir" ]] || { echo "no such directory: $source_dir" >&2; exit 1; }
[[ -f "$config" ]] || { echo "no such config file: $config" >&2; exit 1; }

config_dir=$(dirname "$config")
existing_ca_dir=$(rg -N '^\s*ca_dir\s*=\s*"([^"]+)"' -r '$1' "$config" || true)
ca_dir=${3:-${existing_ca_dir:-issuer/cas}}
[[ "$ca_dir" = /* ]] || ca_dir="$config_dir/$ca_dir"

mkdir -p "$ca_dir"
chmod 700 "$ca_dir"

declare -a labels=()
declare -a subjects=()

shopt -s nullglob
for cert in "$source_dir"/*.pem; do
    openssl x509 -in "$cert" -noout -purpose 2>/dev/null | rg -q '^SSL server CA : Yes$' || continue

    stem=$(basename "$cert" .pem)
    key="$source_dir/$stem.key"
    if [[ ! -f "$key" ]]; then
        echo "skip $stem: no matching $stem.key next to it" >&2
        continue
    fi

    subject=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
    cn=$(openssl x509 -in "$cert" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')

    install -m 600 "$cert" "$key" "$ca_dir/"
    labels+=("$stem")
    subjects+=("${cn:-$subject}")
    printf '%s\t%s\n' "$stem" "$subject"
done
shopt -u nullglob

if [[ ${#labels[@]} -eq 0 ]]; then
    echo "no SSL-server CA pairs found in $source_dir" >&2
    exit 1
fi

rel_ca_dir=$(python3 -c "import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))" "$ca_dir" "$config_dir")

python3 - "$config" "$rel_ca_dir" "${#labels[@]}" "${subjects[0]:-}" <<'PY'
import re
import sys

config_path, ca_dir, count, first_cn = sys.argv[1:5]
count = int(count)
text = open(config_path).read()

def set_or_insert_after(text, key, value, anchor_key):
    active = re.search(rf'(?m)^{key}\s*=\s*"[^"]*"', text)
    if active:
        return re.sub(rf'(?m)^{key}\s*=\s*"[^"]*"', f'{key} = "{value}"', text, count=1)
    anchor = re.search(rf'(?m)^{anchor_key}\s*=.*$', text)
    if not anchor:
        raise SystemExit(f"could not find active '{anchor_key}' line to anchor '{key}' after")
    pos = anchor.end()
    return text[:pos] + f'\n{key} = "{value}"' + text[pos:]

text = re.sub(r'(?m)^mode\s*=\s*"local".*$', 'mode = "directory"', text, count=1)
text = set_or_insert_after(text, 'ca_dir', ca_dir, 'mode')
if count == 1:
    text = set_or_insert_after(text, 'default_issuer', first_cn, 'ca_dir')

open(config_path, 'w').write(text)
PY

echo "updated $config: mode=directory, ca_dir=$rel_ca_dir" >&2
if [[ ${#labels[@]} -gt 1 ]]; then
    echo "multiple issuers found; default_issuer left unset here, set certificates.default_issuer" \
         "or per-endpoint [[endpoints]] issuer = \"<substring of subject>\" manually" >&2
fi
