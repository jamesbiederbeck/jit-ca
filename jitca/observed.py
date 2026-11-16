"""Summarize recorded events into a per-hostname view and endpoint stanzas to promote."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path


def summarize(events_path: Path, configured: set[str] | frozenset[str] = frozenset()) -> list[dict]:
    hosts: dict[str, dict] = {}

    def host(name: str) -> dict:
        return hosts.setdefault(name, {"hostname": name, "configured": name in configured,
                                       "dns_queries": 0, "tls_denied": 0, "handshake_failures": 0, "requests": 0,
                                       "sources": set(), "_paths": Counter()})

    if events_path.exists():
        for line in events_path.read_text().splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind = event.get("event")
            name = event.get("sni") if kind == "tls_handshake_failed" else event.get("hostname")
            if not name:
                continue
            if kind == "dns_query":
                host(name)["dns_queries"] += 1
                if event.get("source"):
                    host(name)["sources"].add(event["source"])
            elif kind == "tls_handshake_failed":
                host(name)["handshake_failures"] += 1
            elif kind == "tls_sni_denied":
                host(name)["tls_denied"] += 1
            elif kind == "http_request":
                entry = host(name)
                entry["requests"] += 1
                entry["_paths"][f"{event.get('method', '?')} {event.get('path', '')}"] += 1
                if event.get("source"):
                    entry["sources"].add(event["source"])
    result = []
    for entry in hosts.values():
        paths = entry.pop("_paths")
        entry["sources"] = sorted(entry["sources"])
        entry["top_requests"] = [f"{count}x {key}" for key, count in paths.most_common(5)]
        result.append(entry)
    return sorted(result, key=lambda e: (-e["requests"], -e["dns_queries"], e["hostname"]))


def endpoint_stanzas(summary: list[dict]) -> str:
    """TOML [[endpoints]] stanzas for observed hostnames that are not configured yet."""
    blocks = []
    for entry in summary:
        if entry["configured"] or not (entry["requests"] or entry["tls_denied"]):
            continue
        blocks.append(f'# observed: {entry["requests"]} request(s), {entry["dns_queries"]} DNS query(ies)\n'
                      f'[[endpoints]]\nhostname = "{entry["hostname"]}"\n')
    return "\n".join(blocks)
