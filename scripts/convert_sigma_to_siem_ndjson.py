import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.elasticsearch.windows import ecs_windows_old
from sigma.pipelines.elasticsearch.kubernetes import ecs_kubernetes
from sigma.pipelines.elasticsearch.zeek import ecs_zeek_beats, ecs_zeek_corelight, zeek_raw


def select_pipeline(rule: SigmaRule):
    ls = getattr(rule, "logsource", None)
    product = (getattr(ls, "product", None) or "").lower()
    service = (getattr(ls, "service", None) or "").lower()
    category = (getattr(ls, "category", None) or "").lower()

    if product == "windows" or "windows" in category:
        if service in {"security", "sysmon"}:
            return ecs_windows()
        return ecs_windows()
    if product == "zeek" or "zeek" in category:
        if "corelight" in service:
            return ecs_zeek_corelight()
        if "raw" in service:
            return zeek_raw()
        return ecs_zeek_beats()
    if product == "kubernetes" or "k8s" in category:
        return ecs_kubernetes()
    return ProcessingPipeline([])


def classify_rule(rule: SigmaRule) -> str:
    ls = getattr(rule, "logsource", None)
    product = (getattr(ls, "product", None) or "").lower()
    service = (getattr(ls, "service", None) or "").lower()
    category = (getattr(ls, "category", None) or "").lower()

    if "windows" in {product, service} or "windows" in category:
        return "windows"
    linux_tokens = {"linux", "unix", "ubuntu", "debian", "redhat", "centos", "rhel"}
    if product in linux_tokens or any(token in category for token in linux_tokens) or any(token in service for token in linux_tokens):
        return "linux"
    return "other"


def convert_rules(rule_paths, group_outputs: dict[str, Path], combined_output: Optional[Path] = None):
    converted = 0
    skipped = 0
    duplicate_ids = 0
    ruleset_ids = set()
    failures = []
    pipeline_stats = Counter()
    group_stats = Counter()

    handles: dict[str, any] = {}
    for group, path in group_outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        handles[group] = path.open("w", encoding="utf-8")

    combined_handle = None
    if combined_output is not None:
        combined_output.parent.mkdir(parents=True, exist_ok=True)
        combined_handle = combined_output.open("w", encoding="utf-8")

    try:
        for path in rule_paths:
            try:
                text = path.read_text(encoding="utf-8")
            except Exception as exc:
                skipped += 1
                failures.append({"path": str(path), "error": f"read: {exc}"})
                continue
            try:
                collection = SigmaCollection.from_yaml(text)
            except Exception as exc:
                skipped += 1
                failures.append({"path": str(path), "error": f"parse: {exc}"})
                continue

            for rule in collection.rules:
                pipeline = select_pipeline(rule)
                pipeline_name = type(pipeline).__name__
                backend = LuceneBackend(pipeline)
                single_collection = SigmaCollection([rule])
                try:
                    docs = backend.convert(single_collection, output_format="siem_rule_ndjson")
                except Exception as exc:
                    skipped += 1
                    failures.append({"path": str(path), "rule": getattr(rule, "title", ""), "error": f"convert: {exc}"})
                    continue

                for doc in docs:
                    rid = doc.get("rule_id") or doc.get("id")
                    if not rid:
                        skipped += 1
                        failures.append({"path": str(path), "rule": getattr(rule, "title", ""), "error": "missing rule id"})
                        continue
                    rid_norm = str(rid).lower()
                    if rid_norm in ruleset_ids:
                        duplicate_ids += 1
                        continue
                    ruleset_ids.add(rid_norm)
                    doc["enabled"] = True
                    group = classify_rule(rule)
                    handle = handles.get(group) or handles.get("other")
                    if handle is None:
                        skipped += 1
                        failures.append({"path": str(path), "rule": getattr(rule, "title", ""), "error": f"no output handle for group {group}"})
                        continue
                    serialized = json.dumps(doc, ensure_ascii=False)
                    handle.write(serialized + "\n")
                    if combined_handle is not None:
                        combined_handle.write(serialized + "\n")
                    group_stats[group] += 1
                    converted += 1
                    pipeline_stats[pipeline_name] += 1
    finally:
        for handle in handles.values():
            handle.close()
        if combined_handle is not None:
            combined_handle.close()

    return {
        "converted": converted,
        "skipped": skipped,
        "duplicates": duplicate_ids,
        "failures": failures,
        "pipeline_stats": pipeline_stats,
        "group_stats": group_stats,
    }


def main():
    parser = argparse.ArgumentParser(description="Convert Sigma rules to Elastic SIEM rule NDJSON")
    parser.add_argument("--rules-dir", default="rules", help="Root directory containing Sigma rule files")
    parser.add_argument("--output", default=None, help="Optional combined output NDJSON path")
    parser.add_argument("--windows-output", default="build/sigma-windows.ndjson", help="Output path for Windows rules")
    parser.add_argument("--linux-output", default="build/sigma-linux.ndjson", help="Output path for Linux rules")
    parser.add_argument("--other-output", default="build/sigma-generic.ndjson", help="Output path for remaining rules")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of rules processed (debug)")
    args = parser.parse_args()

    rules_root = Path(args.rules_dir)
    if not rules_root.exists():
        print(json.dumps({"error": f"rules directory not found: {rules_root}"}), file=sys.stderr)
        sys.exit(1)

    all_paths = sorted(rules_root.rglob("*.yml"))
    if args.limit:
        all_paths = all_paths[: args.limit]

    outputs = {
        "windows": Path(args.windows_output),
        "linux": Path(args.linux_output),
        "other": Path(args.other_output),
    }
    combined_path = Path(args.output) if args.output else None

    stats = convert_rules(all_paths, outputs, combined_path)
    stats["total_files"] = len(all_paths)
    stats["pipeline_stats"] = dict(stats["pipeline_stats"])
    stats["group_stats"] = dict(stats["group_stats"])
    stats["group_outputs"] = {group: str(path) for group, path in outputs.items()}
    if combined_path is not None:
        stats["output"] = str(combined_path)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
