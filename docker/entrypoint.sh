#!/usr/bin/env bash
# Container entrypoint: build the jitca config from JITCA_* environment variables,
# import operator CA pairs from the CA volume with scripts/discover-issuers.sh,
# then exec jitca.
#
# The config persists in JITCA_CONFIG_DIR next to a stamp file. On start:
#   - no config, or the JITCA_* environment changed  => config regenerated (old one kept as .bak)
#   - otherwise the config (including manual edits) is kept, and only its certificate entries
#     (mode / ca_dir / default_issuer plus the staged copies in <state>/issuers) are checked
#     against the CA volume. If the volume has CA pairs the config does not reference, the
#     config references pairs that differ from the volume, or the staged copies changed, those
#     entries are deleted and rebuilt (and reset to the local demo CA if the volume is empty).
#
#   JITCA_ENDPOINTS              comma/space separated hostnames (explicit endpoints, 204 + logged)
#   JITCA_EXTRA_CONFIG           TOML file appended verbatim (full [[endpoints]] blocks with routes)
#   JITCA_REDIRECT_IPV4          address DNS answers with (required for JITCA_DNS_ANSWER_ALL)
#   JITCA_ALLOWED_CLIENTS        comma/space separated CIDRs (default 127.0.0.1/32)
#   JITCA_DNS_ANSWER_ALL         true|false: answer every A query with the redirect address
#   JITCA_DEFAULT_ENDPOINT       true|false: serve + log hostnames that are not explicit endpoints
#   JITCA_DEFAULT_MAX_HOSTNAMES  cap on distinct default-endpoint hostnames (default 100)
#   JITCA_CAPTURE_BODIES         true|false: write raw request/response bodies to <state>/captures (false)
#   JITCA_CAPTURE_MAX_BODY_BYTES per-body cap (262144); JITCA_CAPTURE_MAX_FILES file cap (1000)
#   JITCA_CAPTURE_REDACT         true|false: store key-name-redacted JSON only, skip non-JSON (false)
#   JITCA_LOG_STDOUT             true|false: also print each event (JSON line) to stdout / `docker logs` (false)
#   JITCA_LEAF_KEY               rsa2048|p256 (default rsa2048)
#   JITCA_LEAF_DAYS              leaf validity in days (default 30)
#   JITCA_DEFAULT_ISSUER         substring of a CA subject; with >1 CA and none set, the first CA by
#                                filename with a unique subject is used (and logged)
#   JITCA_CA_SRC                 CA pool mount point (default /ca-src); *.pem/*.key pairs, read-only
#   JITCA_STATE_DIR              state directory: certificates, events, staged issuers (default /state)
#   JITCA_CONFIG_DIR             where config.toml and its stamp live (default: JITCA_STATE_DIR)
#   JITCA_NO_EXEC=1              generate the config and stop (used by tests)
# Any arguments are passed to jitca as the subcommand (default: serve).
set -euo pipefail

state=${JITCA_STATE_DIR:-/state}
ca_src=${JITCA_CA_SRC:-/ca-src}
discover=${JITCA_DISCOVER_SCRIPT:-/app/scripts/discover-issuers.sh}
config_dir=${JITCA_CONFIG_DIR:-$state}
config=$config_dir/config.toml
stamp=$config_dir/.entrypoint-stamp
issuers=$state/issuers

die() { echo "entrypoint: $*" >&2; exit 1; }
note() { echo "entrypoint: $*" >&2; }

bool() { # bool VAR default -> true|false
    local value=${!1:-$2}
    case ${value,,} in
        true|1|yes|on) echo true ;;
        false|0|no|off|"") echo false ;;
        *) die "$1 must be true or false (got '$value')" ;;
    esac
}

split() { # split STRING -> one item per line
    local IFS=$', \t\n' item
    for item in $1; do printf '%s\n' "$item"; done
}

toml_string() { # reject anything that would need TOML escaping
    [[ $1 != *[\"\\]* && $1 != *[[:cntrl:]]* ]] || die "unsupported characters in value: $1"
    printf '"%s"' "$1"
}

host_re='^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$'
ipv4_re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
cidr_re='^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'
int_re='^[0-9]+$'

answer_all=$(bool JITCA_DNS_ANSWER_ALL false)
default_endpoint=$(bool JITCA_DEFAULT_ENDPOINT false)
capture=$(bool JITCA_CAPTURE_BODIES false)
log_stdout=$(bool JITCA_LOG_STDOUT false)
capture_redact=$(bool JITCA_CAPTURE_REDACT false)
capture_body=${JITCA_CAPTURE_MAX_BODY_BYTES:-262144}
capture_files=${JITCA_CAPTURE_MAX_FILES:-1000}
[[ $capture_body =~ ^[0-9]+$ && $capture_files =~ ^[0-9]+$ ]] \
    || die "JITCA_CAPTURE_MAX_BODY_BYTES and JITCA_CAPTURE_MAX_FILES must be integers"
redirect=${JITCA_REDIRECT_IPV4:-}
leaf_key=${JITCA_LEAF_KEY:-rsa2048}
leaf_days=${JITCA_LEAF_DAYS:-30}
max_hostnames=${JITCA_DEFAULT_MAX_HOSTNAMES:-100}
[[ -z $redirect || $redirect =~ $ipv4_re ]] || die "JITCA_REDIRECT_IPV4 must be an IPv4 address"
[[ $answer_all == false || -n $redirect ]] || die "JITCA_DNS_ANSWER_ALL needs JITCA_REDIRECT_IPV4"
[[ $leaf_key == rsa2048 || $leaf_key == p256 ]] || die "JITCA_LEAF_KEY must be rsa2048 or p256"
[[ $leaf_days =~ $int_re ]] || die "JITCA_LEAF_DAYS must be an integer"
[[ $max_hostnames =~ $int_re ]] || die "JITCA_DEFAULT_MAX_HOSTNAMES must be an integer"

clients=()
while read -r item; do
    [[ -z $item ]] && continue
    [[ $item =~ $cidr_re ]] || die "JITCA_ALLOWED_CLIENTS: bad CIDR '$item'"
    clients+=("$(toml_string "$item")")
done < <(split "${JITCA_ALLOWED_CLIENTS:-127.0.0.1/32}")
[[ ${#clients[@]} -gt 0 ]] || die "JITCA_ALLOWED_CLIENTS is empty"
clients_toml=$(IFS=,; echo "${clients[*]}" | sed 's/,/, /g')

mkdir -p "$state" "$config_dir"

hash_stdin() { sha256sum | cut -d' ' -f1; }
env_hash() {
    {
        env | { grep '^JITCA_' || true; } | { grep -v '^JITCA_NO_EXEC=' || true; } | sort
        if [[ -n ${JITCA_EXTRA_CONFIG:-} && -f ${JITCA_EXTRA_CONFIG} ]]; then sha256sum "$JITCA_EXTRA_CONFIG"; fi
    } | hash_stdin
}
dir_hash() { # dir -> hash of the *.pem/*.key contents and names (empty dir => hash of nothing)
    [[ -d $1 ]] || { printf '' | hash_stdin; return; }
    find "$1" -maxdepth 1 -type f \( -name '*.pem' -o -name '*.key' \) -printf '%f\n' | sort \
        | while read -r f; do printf '%s ' "$f"; sha256sum <"$1/$f"; done | hash_stdin
}
stamp_get() { sed -n "s/^$1=//p" "$stamp" 2>/dev/null | head -1; }

generate_config() {
    local tmp item name
    tmp=$(mktemp "$config_dir/config.toml.XXXXXX")
    {
        echo "# Generated by docker/entrypoint.sh. Manual edits are kept until the JITCA_* environment changes."
        echo "[network]"
        echo 'dns_host = "0.0.0.0"'
        echo 'dns_port = 15353'
        echo 'tls_host = "0.0.0.0"'
        echo 'tls_port = 18443'
        [[ -n $redirect ]] && echo "redirect_ipv4 = $(toml_string "$redirect")"
        echo "allowed_clients = [$clients_toml]"
        echo "dns_answer_all = $answer_all"
        echo "[certificates]"
        echo 'mode = "local"'
        echo "state_dir = $(toml_string "$state")"
        echo "leaf_days = $leaf_days"
        echo "leaf_key = $(toml_string "$leaf_key")"
        echo "[http]"
        echo "max_body_bytes = 65536"
        if [[ $log_stdout == true ]]; then
            printf '[logging]\nstdout = true\n'
        fi
        if [[ $capture == true ]]; then
            printf '[capture]\nenabled = true\nmax_body_bytes = %s\nmax_files = %s\nredact = %s\n' \
                "$capture_body" "$capture_files" "$capture_redact"
        fi
        while read -r name; do
            [[ -z $name ]] && continue
            [[ $name =~ $host_re ]] || die "JITCA_ENDPOINTS: bad hostname '$name'"
            printf '[[endpoints]]\nhostname = %s\n' "$(toml_string "$name")"
        done < <(split "${JITCA_ENDPOINTS:-}")
        if [[ -n ${JITCA_EXTRA_CONFIG:-} ]]; then
            [[ -f $JITCA_EXTRA_CONFIG ]] || die "JITCA_EXTRA_CONFIG not found: $JITCA_EXTRA_CONFIG"
            cat "$JITCA_EXTRA_CONFIG"
            echo
        fi
        if [[ $default_endpoint == true ]]; then
            printf '[default_endpoint]\nmax_hostnames = %s\n' "$max_hostnames"
        fi
    } >"$tmp" || { rm -f "$tmp"; die "could not write config"; }
    chmod 600 "$tmp"
    mv -f "$tmp" "$config"
}

# Delete the certificate entries (mode, ca_dir, default_issuer) from [certificates] and reset
# the table to the local demo CA, leaving everything else in the file alone.
strip_cert_entries() {
    python3 - "$config" "$state" <<'PY'
import re
import sys

path, state = sys.argv[1:3]
header = re.compile(r'^\s*\[\[?\s*([^\]\s]+)\s*\]\]?\s*(#.*)?$')
entry = re.compile(r'^\s*(mode|ca_dir|default_issuer)\s*=')
out, section, seen = [], None, False
for line in open(path).read().split("\n"):
    match = header.match(line)
    if match:
        section = match.group(1)
        out.append(line)
        if section == "certificates" and not line.lstrip().startswith("[["):
            seen = True
            out.append('mode = "local"')
        continue
    if section == "certificates" and entry.match(line):
        continue
    out.append(line)
text = "\n".join(out)
if not seen:
    text = text.rstrip("\n") + f'\n[certificates]\nmode = "local"\nstate_dir = "{state}"\n'
open(path, "w").write(text)
PY
}

cert_entries_present() { # config references a complete directory-issuer setup
    grep -q '^mode = "directory"' "$config" && grep -q '^ca_dir = ' "$config" \
        && grep -q '^default_issuer = ' "$config"
}

# Set (or replace) default_issuer, placing it right after ca_dir. Rewritten line by line so
# subject strings with sed-special characters (| & \) are safe.
set_default_issuer() {
    local value tmp line
    value=$(toml_string "$1")
    tmp=$(mktemp "$config_dir/config.toml.XXXXXX")
    while IFS= read -r line || [[ -n $line ]]; do
        case $line in
            "default_issuer = "*) ;;
            "ca_dir = "*) printf '%s\n' "$line" "default_issuer = $value" ;;
            *) printf '%s\n' "$line" ;;
        esac
    done <"$config" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$config"
}

# Several CAs and no explicit JITCA_DEFAULT_ISSUER: default to the first CA (by filename) whose
# full subject identifies exactly one CA. The loader matches the selector as a case-insensitive
# substring of each subject, so a subject that is contained in another CA's subject is skipped.
pick_default_issuer() { # $1 = "<stem>\t<subject>" lines from discover-issuers.sh
    local -a stems=() subjects=() lower=()
    local stem subject i j hits
    while IFS=$'\t' read -r stem subject; do
        [[ -n $stem ]] || continue
        stems+=("$stem"); subjects+=("$subject"); lower+=("${subject,,}")
    done <<<"$1"
    for i in "${!stems[@]}"; do
        hits=0
        for j in "${!lower[@]}"; do
            [[ ${lower[$j]} == *"${lower[$i]}"* ]] && hits=$((hits + 1))
        done
        if (( hits == 1 )); then
            set_default_issuer "${subjects[$i]}"
            note "found ${#stems[@]} CAs and no JITCA_DEFAULT_ISSUER; defaulting to '${stems[$i]}' (${subjects[$i]})"
            note "set JITCA_DEFAULT_ISSUER (a substring of a CA subject) or per-endpoint 'issuer' to choose another"
            return 0
        fi
    done
    die "found ${#stems[@]} CAs in $ca_src but none has a subject that is unique; set JITCA_DEFAULT_ISSUER"
}

import_issuers() {
    rm -rf "$issuers"
    note "discovering issuers in $ca_src"
    local found
    found=$("$discover" "$ca_src" "$config" "$issuers") \
        || die "no usable CA pairs in $ca_src (need <stem>.pem + <stem>.key with CA:TRUE / keyCertSign)"
    printf '%s\n' "$found" >&2
    if [[ -n ${JITCA_DEFAULT_ISSUER:-} ]]; then
        set_default_issuer "$JITCA_DEFAULT_ISSUER"
    elif ! grep -q '^default_issuer = ' "$config"; then
        pick_default_issuer "$found"
    fi
}

have_pool=false
compgen -G "$ca_src/*.pem" >/dev/null && have_pool=true
env_now=$(env_hash)
ca_now=$(dir_hash "$ca_src")

reason=""
if [[ ! -f $config ]]; then
    reason="no config yet"
elif [[ $(stamp_get env) != "$env_now" ]]; then
    reason="JITCA_* environment changed"
elif [[ ${JITCA_REGENERATE_CONFIG:-} == 1 ]]; then
    reason="JITCA_REGENERATE_CONFIG=1"
fi
if [[ -n $reason ]]; then
    note "regenerating config ($reason)"
    [[ -f $config ]] && cp -f "$config" "$config.bak"
    generate_config
    rebuild=1
else
    rebuild=""
    if [[ $have_pool == true ]]; then
        cert_entries_present || rebuild="config has no directory-issuer entries but $ca_src has CA pairs"
        [[ -z $rebuild && $(stamp_get ca) != "$ca_now" ]] && rebuild="CA pairs in $ca_src changed since the config was built"
        [[ -z $rebuild && $(stamp_get staged) != "$(dir_hash "$issuers")" ]] && rebuild="staged issuers in $issuers do not match what was imported"
    else
        { cert_entries_present || [[ -d $issuers ]]; } && rebuild="$ca_src has no CA pairs but the config references directory issuers"
    fi
    if [[ -n $rebuild ]]; then
        note "reconciling issuers: $rebuild"
        strip_cert_entries
    else
        note "config up to date"
    fi
fi

if [[ -n $rebuild ]]; then
    if [[ $have_pool == true ]]; then
        import_issuers
    else
        rm -rf "$issuers"
        note "no CA pairs in $ca_src; using the local demo CA"
    fi
    {
        echo "env=$env_now"
        echo "ca=$ca_now"
        echo "staged=$(dir_hash "$issuers")"
    } >"$stamp"
fi

[[ ${JITCA_NO_EXEC:-} == 1 ]] && exit 0
if [[ $# -eq 0 ]]; then set -- serve; fi
exec jitca --config "$config" "$@"
