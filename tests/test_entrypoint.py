import os
import shutil
import subprocess
from pathlib import Path

import pytest

from jitca.config import load_config
from test_discover_issuers import write_pair

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
DISCOVER = ROOT / "scripts" / "discover-issuers.sh"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("openssl", "rg", "bash")),
    reason="entrypoint tests need bash, openssl and ripgrep")


def run_entrypoint(tmp_path, **env):
    state = tmp_path / "state"
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir(exist_ok=True)
    environment = {"PATH": os.environ["PATH"], "JITCA_NO_EXEC": "1", "JITCA_STATE_DIR": str(state),
                   "JITCA_CA_SRC": str(ca_src), "JITCA_DISCOVER_SCRIPT": str(DISCOVER), **env}
    result = subprocess.run(["bash", str(ENTRYPOINT)], env=environment, capture_output=True, text=True)
    return result, state / "config.toml", ca_src


def test_builds_config_from_environment(tmp_path):
    result, config, _ = run_entrypoint(
        tmp_path, JITCA_ENDPOINTS="Robot.example.test, other.example", JITCA_REDIRECT_IPV4="192.0.2.45",
        JITCA_ALLOWED_CLIENTS="192.0.2.0/24 10.0.0.0/8", JITCA_DNS_ANSWER_ALL="true",
        JITCA_DEFAULT_ENDPOINT="yes", JITCA_DEFAULT_MAX_HOSTNAMES="7", JITCA_LEAF_KEY="p256", JITCA_LEAF_DAYS="10")
    assert result.returncode == 0, result.stderr
    assert "using the local demo CA" in result.stderr
    cfg = load_config(config)
    assert set(cfg.endpoints) == {"robot.example.test", "other.example"}
    assert cfg.redirect_ipv4 == "192.0.2.45" and cfg.dns_answer_all
    assert cfg.default_endpoint is not None and cfg.default_max_hostnames == 7
    assert cfg.leaf_key == "p256" and cfg.leaf_days == 10 and cfg.issuer_mode == "local"
    assert cfg.allows_client("192.0.2.7") and cfg.allows_client("10.1.2.3")
    assert not cfg.allows_client("192.0.3.7")
    assert (config.stat().st_mode & 0o777) == 0o600


def test_safe_defaults_and_extra_config(tmp_path):
    extra = tmp_path / "extra.toml"
    extra.write_text('[[endpoints]]\nhostname = "x.example"\n[[endpoints.routes]]\npath = "/s"\nbody = "ok"\n')
    result, config, _ = run_entrypoint(tmp_path, JITCA_EXTRA_CONFIG=str(extra))
    assert result.returncode == 0, result.stderr
    cfg = load_config(config)
    assert cfg.default_endpoint is None and not cfg.dns_answer_all
    assert cfg.allows_client("127.0.0.1") and not cfg.allows_client("192.0.2.7")
    assert cfg.endpoints["x.example"].routes[0].body == "ok"


def test_imports_ca_volume_into_directory_mode(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    write_pair(ca_src, "leafish", "Not A CA", ca=False)
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_DEFAULT_ENDPOINT="true")
    assert result.returncode == 0, result.stderr
    cfg = load_config(config)
    assert cfg.issuer_mode == "directory" and cfg.default_issuer == "Test OV TLS CA"
    assert sorted(p.name for p in (tmp_path / "state" / "issuers").iterdir()) == ["ov.key", "ov.pem"]


def test_multiple_cas_pick_a_default_unless_overridden(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    write_pair(ca_src, "ev", "Test EV TLS CA", ca=True)
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_DEFAULT_ENDPOINT="true")
    assert result.returncode == 0, result.stderr
    assert "defaulting to 'ev'" in result.stderr and "JITCA_DEFAULT_ISSUER" in result.stderr
    cfg = load_config(config)  # must load: default_endpoint in directory mode needs a default issuer
    assert cfg.default_issuer == "CN=Test EV TLS CA"
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_DEFAULT_ENDPOINT="true",
                                       JITCA_DEFAULT_ISSUER="OV TLS")
    assert result.returncode == 0 and "defaulting" not in result.stderr
    assert load_config(config).default_issuer == "OV TLS"


def test_default_pick_skips_subjects_contained_in_other_subjects(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "a", "Lab CA", ca=True)      # "cn=lab ca" is a substring of the next subject
    write_pair(ca_src, "b", "Lab CA 2", ca=True)
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_DEFAULT_ENDPOINT="true")
    assert result.returncode == 0, result.stderr
    assert "defaulting to 'b'" in result.stderr
    assert load_config(config).default_issuer == "CN=Lab CA 2"


def test_issuer_with_sed_special_characters_is_written_safely(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "a", "Acme & Sons | Root", ca=True)
    write_pair(ca_src, "b", "Other CA", ca=True)
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_DEFAULT_ENDPOINT="true")
    assert result.returncode == 0, result.stderr
    assert load_config(config).default_issuer == "CN=Acme & Sons | Root"


def test_config_missing_default_issuer_is_not_reported_up_to_date(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    first, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_DEFAULT_ENDPOINT="true")
    assert first.returncode == 0, first.stderr
    config.write_text("\n".join(line for line in config.read_text().splitlines()
                                if not line.startswith("default_issuer = ")))
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_DEFAULT_ENDPOINT="true")
    assert second.returncode == 0 and "reconciling issuers" in second.stderr, second.stderr
    assert load_config(config).default_issuer == "Test OV TLS CA"


def test_stale_copies_are_removed_when_a_ca_leaves_the_volume(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    write_pair(ca_src, "ev", "Test EV TLS CA", ca=True)
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert result.returncode == 0, result.stderr
    for stale in list(ca_src.glob("ev.*")):
        stale.unlink()
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in (tmp_path / "state" / "issuers").iterdir()) == ["ov.key", "ov.pem"]
    assert load_config(config).default_issuer == "Test OV TLS CA"


def test_pems_without_usable_ca_fail_instead_of_falling_back(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "leaf", "Not A CA", ca=False)
    result, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert result.returncode != 0 and "no usable CA pairs" in result.stderr


@pytest.mark.parametrize("env,message", [
    ({"JITCA_DNS_ANSWER_ALL": "true"}, "needs JITCA_REDIRECT_IPV4"),
    ({"JITCA_DNS_ANSWER_ALL": "maybe"}, "must be true or false"),
    ({"JITCA_REDIRECT_IPV4": "not-an-ip"}, "IPv4 address"),
    ({"JITCA_ALLOWED_CLIENTS": "1.2.3.4/8; rm -rf /"}, "bad CIDR"),
    ({"JITCA_ENDPOINTS": "bad host!"}, "bad hostname"),
    ({"JITCA_ENDPOINTS": 'x"y.example'}, "bad hostname"),
    ({"JITCA_LEAF_KEY": "rsa4096"}, "rsa2048 or p256"),
    ({"JITCA_EXTRA_CONFIG": "/nonexistent.toml"}, "not found"),
])
def test_invalid_environment_is_rejected(tmp_path, env, message):
    result, config, _ = run_entrypoint(tmp_path, **{"JITCA_ENDPOINTS": "ok.example", **env})
    assert result.returncode != 0 and message in result.stderr
    assert not config.exists()


# --- persistent config + reconciliation against the CA volume -------------------------------

def cert_lines(config):
    return [line for line in config.read_text().splitlines()
            if line.startswith(("mode = ", "ca_dir = ", "default_issuer = "))]


def staged(tmp_path):
    return sorted(p.name for p in (tmp_path / "state" / "issuers").iterdir()) \
        if (tmp_path / "state" / "issuers").exists() else []


def test_unchanged_start_keeps_config_and_manual_edits(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    first, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert first.returncode == 0, first.stderr
    config.write_text(config.read_text() + '\n[[endpoints]]\nhostname = "hand-added.example"\n')
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert second.returncode == 0, second.stderr
    assert "config up to date" in second.stderr and "reconciling" not in second.stderr
    assert "hand-added.example" in load_config(config).endpoints


def test_changed_environment_regenerates_config_and_keeps_backup(tmp_path):
    first, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert first.returncode == 0, first.stderr
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="y.example")
    assert second.returncode == 0 and "regenerating config (JITCA_* environment changed)" in second.stderr
    assert set(load_config(config).endpoints) == {"y.example"}
    assert 'hostname = "x.example"' in (config.parent / "config.toml.bak").read_text()


def test_ca_added_after_first_start_is_picked_up(tmp_path):
    first, config, ca_src = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert first.returncode == 0 and load_config(config).issuer_mode == "local"
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert second.returncode == 0 and "reconciling issuers" in second.stderr, second.stderr
    cfg = load_config(config)
    assert cfg.issuer_mode == "directory" and cfg.default_issuer == "Test OV TLS CA"
    assert staged(tmp_path) == ["ov.key", "ov.pem"]


def test_replaced_ca_pair_is_restaged(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Old CA", ca=True)
    first, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert first.returncode == 0 and load_config(config).default_issuer == "Old CA"
    write_pair(ca_src, "ov", "New CA", ca=True)
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert second.returncode == 0 and "changed since the config was built" in second.stderr
    assert load_config(config).default_issuer == "New CA"
    assert (tmp_path / "state" / "issuers" / "ov.pem").read_bytes() == (ca_src / "ov.pem").read_bytes()
    # A second CA that leaves one CA unambiguous is also rediscovered, not left stale.
    (ca_src / "ov.pem").unlink()
    (ca_src / "ov.key").unlink()
    write_pair(ca_src, "ev", "EV CA", ca=True)
    third, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert third.returncode == 0 and staged(tmp_path) == ["ev.key", "ev.pem"]
    assert load_config(config).default_issuer == "EV CA"


def test_emptied_ca_volume_resets_to_local_demo_ca(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    first, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert first.returncode == 0 and load_config(config).issuer_mode == "directory"
    for path in ca_src.iterdir():
        path.unlink()
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert second.returncode == 0 and "no CA pairs but the config references" in second.stderr
    cfg = load_config(config)
    assert cfg.issuer_mode == "local" and cfg.default_issuer is None and cfg.ca_dir is None
    assert staged(tmp_path) == []
    assert cert_lines(config) == ['mode = "local"']


def test_tampered_staged_copy_is_restored(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    first, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert first.returncode == 0, first.stderr
    (tmp_path / "state" / "issuers" / "ov.pem").write_text("garbage")
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert second.returncode == 0 and "staged issuers" in second.stderr
    assert (tmp_path / "state" / "issuers" / "ov.pem").read_bytes() == (ca_src / "ov.pem").read_bytes()


def test_deleted_cert_entries_are_remade_without_touching_the_rest(tmp_path):
    ca_src = tmp_path / "ca-src"
    ca_src.mkdir()
    write_pair(ca_src, "ov", "Test OV TLS CA", ca=True)
    first, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert first.returncode == 0, first.stderr
    kept = config.read_text() + '\n[[endpoints]]\nhostname = "hand-added.example"\n'
    config.write_text("\n".join(line for line in kept.splitlines()
                                if not line.startswith(("mode = ", "ca_dir = ", "default_issuer = "))))
    second, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert second.returncode == 0 and "reconciling issuers" in second.stderr, second.stderr
    cfg = load_config(config)
    assert cfg.issuer_mode == "directory" and set(cfg.endpoints) == {"x.example", "hand-added.example"}
    assert sorted(cert_lines(config)) == sorted(
        ['mode = "directory"', 'ca_dir = "issuers"', 'default_issuer = "Test OV TLS CA"'])


def test_separate_config_dir_keeps_config_and_stamp_out_of_state(tmp_path):
    result, _, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_CONFIG_DIR=str(tmp_path / "cfg"))
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "cfg" / "config.toml").exists() and (tmp_path / "cfg" / ".entrypoint-stamp").exists()
    assert not (tmp_path / "state" / "config.toml").exists()
    assert load_config(tmp_path / "cfg" / "config.toml").state_dir == (tmp_path / "state").resolve()


def test_capture_environment_builds_capture_table(tmp_path):
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_CAPTURE_BODIES="true",
                                       JITCA_CAPTURE_MAX_BODY_BYTES="4096", JITCA_CAPTURE_MAX_FILES="50",
                                       JITCA_CAPTURE_REDACT="true")
    assert result.returncode == 0, result.stderr
    capture = load_config(config).capture
    assert (capture.max_body_bytes, capture.max_files, capture.redact) == (4096, 50, True)
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert result.returncode == 0 and load_config(config).capture is None


def test_capture_environment_is_validated(tmp_path):
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_CAPTURE_MAX_FILES="lots")
    assert result.returncode != 0 and "must be integers" in result.stderr and not config.exists()


def test_log_stdout_environment_builds_logging_table(tmp_path):
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example", JITCA_LOG_STDOUT="true")
    assert result.returncode == 0, result.stderr
    assert load_config(config).log_stdout is True
    result, config, _ = run_entrypoint(tmp_path, JITCA_ENDPOINTS="x.example")
    assert result.returncode == 0 and load_config(config).log_stdout is False
