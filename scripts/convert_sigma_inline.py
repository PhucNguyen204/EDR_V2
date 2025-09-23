from pathlib import Path
import json, sys
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend

def main():
    out_path = Path('/w/out/sigma-linux-all.esql.ndjson')
    out_path.parent.mkdir(parents=True, exist_ok=True)
    f = out_path.open('w', encoding='utf-8')
    indexes = [
        "logs-linux-journald-*",
        "logs-linux-auditd-*",
        "logs-linux-syslog-*",
    ]
    backend = ESQLBackend()

    roots = ['/w/rules/rules/linux/auditd','/w/rules/rules/linux/builtin']
    for root in roots:
        for p in Path(root).rglob('*.yml'):
            try:
                col = SigmaCollection.from_yaml(p.read_text(encoding='utf-8'))
            except Exception as e:
                print(f"[WARN] load {p} failed: {e}", file=sys.stderr)
                continue
            for rule in col.rules:
                try:
                    q = backend.convert_rule(rule)
                except Exception as e:
                    print(f"[WARN] backend convert failed for {p}: {e}", file=sys.stderr)
                    continue
                rid = (getattr(rule, 'id', None) or p.stem).lower()
                doc = {
                    "name": f"SIGMA - {rule.title}",
                    "id": rid,
                    "author": [rule.author] if isinstance(rule.author, str) else (rule.author or []),
                    "description": rule.description or "",
                    "references": rule.references or [],
                    "enabled": True,
                    "interval": "1m",
                    "from": "now-1m",
                    "rule_id": rid,
                    "false_positives": rule.falsepositives or [],
                    "immutable": False,
                    "output_index": "",
                    "meta": {"from": "1m"},
                    "risk_score": 21,
                    "severity": (str(getattr(getattr(rule, 'level', None), 'name', 'low')).lower() if getattr(rule, 'level', None) else "low"),
                    "threat": [],
                    "severity_mapping": [],
                    "to": "now",
                    "version": 1,
                    "max_signals": 1000,
                    "exceptions_list": [],
                    "setup": "",
                    "type": "esql",
                    "note": "",
                    "license": "DRL",
                    "language": "esql",
                    "query": q,
                    "tags": [f"{t.namespace}-{t.name}" for t in getattr(rule, 'tags', [])] if getattr(rule, 'tags', None) else [],
                    "index": indexes,
                    "actions": [],
                    "related_integrations": [],
                    "required_fields": [],
                    "risk_score_mapping": []
                }
                f.write(json.dumps(doc, ensure_ascii=False) + "\n")
    f.close()
    print("DONE")

if __name__ == '__main__':
    main()

