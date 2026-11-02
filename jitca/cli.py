from __future__ import annotations

import argparse
import json
from pathlib import Path
import threading

from .certs import CertificateStore
from .config import load_config
from .service import JITCAService


def main(argv=None):
    parser = argparse.ArgumentParser(prog="jitca", description="DNS-prewarmed local TLS emulator POC")
    parser.add_argument("--config", default="config.toml", help="Path to TOML configuration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Run DNS and TLS listeners")
    sub.add_parser("certs", help="List issued cached certificates")
    sub.add_parser("issuer", help="Show issuer validity and test CA location")
    events = sub.add_parser("events", help="Print recorded JSONL observations")
    events.add_argument("--tail", type=int, default=20)
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    if args.command == "serve":
        service = JITCAService(cfg)
        service.start()
        print(f"JIT CA DNS {service.dns_address}; HTTPS {service.tls_address}", flush=True)
        print(f"Issuer mode: {cfg.issuer_mode}; endpoints: {', '.join(cfg.endpoints)}", flush=True)
        print("Ctrl-C to stop", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            service.stop()
    elif args.command == "certs":
        print(json.dumps(CertificateStore(cfg).all_metadata(), indent=2))
    elif args.command == "issuer":
        store = CertificateStore(cfg)
        if cfg.issuer_mode == "directory":
            print(json.dumps({"mode": "directory", "ca_dir": str(cfg.ca_dir),
                              "issuers": {label: {"subject": rec.subject,
                                                  "not_after": rec.not_after.isoformat()}
                                         for label, rec in sorted(store.issuers.items())},
                              "endpoints": {h: store.endpoint_issuer[h] for h in cfg.endpoints}}, indent=2))
        else:
            print(json.dumps({"mode": cfg.issuer_mode, "subject": store.issuer_cert.subject.rfc4514_string(),
                              "not_before": store.issuer_cert.not_valid_before_utc.isoformat(),
                              "not_after": store.not_after.isoformat(),
                              "demo_ca_cert": str(store.root_ca_path) if store.root_ca_path else None}, indent=2))
    elif args.command == "events":
        path = cfg.state_dir / "events.jsonl"
        if path.exists():
            print("".join(path.read_text().splitlines(keepends=True)[-args.tail:]), end="")


if __name__ == "__main__":
    main()
