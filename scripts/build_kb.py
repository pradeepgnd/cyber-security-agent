#!/usr/bin/env python3
"""Wipe and rebuild all Chroma collections. Optional --smoke retrieval checks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.rag.ingest import rebuild_collections  # noqa: E402
from src.rag.retrievers import reset_client, retrieve  # noqa: E402


def smoke() -> int:
    reset_client()
    cve = retrieve("cve", "log4j jndi rce", k=3)
    det = retrieve("detections", "repeated failed password", k=3)
    print("\nSmoke - cve <- 'log4j jndi rce'")
    for text, cid, score in cve:
        print(f"  {cid:30s}  score={score:.3f}  {text.splitlines()[0][:60]}")
    print("Smoke - detections <- 'repeated failed password'")
    for text, cid, score in det:
        print(f"  {cid:30s}  score={score:.3f}  {text.splitlines()[0][:60]}")

    cve_ids = " ".join(cid for _, cid, _ in cve)
    det_ids = " ".join(cid for _, cid, _ in det)
    ok = True
    if "CVE-2021-44228" not in cve_ids and "44228" not in cve_ids:
        print("FAIL: expected CVE-2021-44228 as a top CVE hit")
        ok = False
    if "brute" not in det_ids.lower() and "ssh-brute" not in det_ids.lower():
        # accept if the top document text mentions brute force
        top = (det[0][0] + det[0][1]).lower() if det else ""
        if "brute" not in top and "failed password" not in top:
            print("FAIL: expected a brute-force detection as a top hit")
            ok = False
    if ok:
        print("\nSmoke checks passed.")
        return 0
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild the local knowledge-base index")
    parser.add_argument("--smoke", action="store_true", help="run retrieval smoke tests")
    parser.add_argument("--no-wipe", action="store_true", help="do not delete existing collections")
    args = parser.parse_args()

    print("Rebuilding Chroma collections...")
    stats = rebuild_collections(wipe=not args.no_wipe)
    reset_client()
    print(f"{'collection':<14} {'docs':>6} {'chunks':>8}")
    print("-" * 30)
    for name, counts in stats.items():
        print(f"{name:<14} {counts['docs']:>6} {counts['chunks']:>8}")
        if counts["docs"] == 0 or counts["chunks"] == 0:
            print(f"WARNING: {name} is empty")
    if args.smoke:
        return smoke()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
