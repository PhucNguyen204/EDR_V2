from pathlib import Path
import json, sys
from typing import List

from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend


LINUX_RULE_ROOTS: List[str] = [
    "/w/rules/rules/linux/auditd",
    "/w/rules/rules/linux/builtin",
]

INDEX_PATTERNS: List[str] = [
    "logs-linux-journald-*",
    "logs-linux-auditd-*",
    "logs-linux-syslog-*",
]


def main():
    out_path = Path("/w/out/sigma-linux-lucene-rules.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    backend = LuceneBackend()

    created = 0
    skipped = 0
    with out_path.open("w", encoding="utf-8") as f:
        for root in LINUX_RULE_ROOTS:
            for p in Path(root).rglob("*.yml"):
                try:
                    col = SigmaCollection.from_yaml(p.read_text(encoding="utf-8"))
                except Exception as e:
                    print(f"[WARN] load {p} failed: {e}", file=sys.stderr)
                    skipped += 1
                    continue
                for rule in col.rules:
                    try:
                        q = backend.convert_rule(rule)
                    except Exception as e:
                        print(f"[WARN] convert {p} failed: {e}", file=sys.stderr)
                        skipped += 1
                        continue

                    rid = (getattr(rule, "id", None) or p.stem).lower()
                    name = f"SIGMA - {rule.title}"
                    desc = rule.description or ""
                    sev = (
                        str(getattr(getattr(rule, "level", None), "name", "low")).lower()
                        if getattr(rule, "level", None)
                        else "low"
                    )
                    # Kibana detection engine create payload (query rule - lucene)
                    doc = {
                        "name": name[:256],
                        "rule_id": rid,
                        "description": desc,
                        "risk_score": 21,
                        "severity": sev if sev in ("low", "medium", "high", "critical") else "low",
                        "interval": "1m",
                        "from": "now-1m",
                        "enabled": True,
                        "type": "query",
                        "language": "lucene",
                        "index": INDEX_PATTERNS,
                        "query": q,
                        # Optional fields that Kibana accepts; keep minimal for compatibility
                        "tags": [f"{t.namespace}-{t.name}" for t in getattr(rule, "tags", [])] if getattr(rule, "tags", None) else [],
                        "author": [rule.author] if isinstance(rule.author, str) else (rule.author or []),
                        "references": rule.references or [],
                        "max_signals": 1000,
                    }
                    f.write(json.dumps(doc, ensure_ascii=False) + "\n")
                    created += 1

    print(json.dumps({"created": created, "skipped": skipped, "output": str(out_path)}))


if __name__ == "__main__":
    main()

