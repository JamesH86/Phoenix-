"""Owner-operated Phoenix monthly subscription key issuer."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phoenix_subscriptions import SubscriptionError, SubscriptionStore, catalog


def config_root() -> Path:
    override = str(os.environ.get("PHOENIX_CONFIG_DIR", "") or "").strip()
    if override:
        return Path(override).expanduser()
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or str(Path.home())
    return Path(base).expanduser() / "PhoenixGuardian"


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Phoenix monthly subscription control keys")
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("catalog")
    subparsers.add_parser("list")
    issue_parser = subparsers.add_parser("issue")
    issue_parser.add_argument("tier", choices=("demo", "solo", "base", "enterprise", "government"))
    issue_parser.add_argument("--customer", default="", help="Private customer label; do not use payment-card data")
    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("key_id")
    args = parser.parse_args()
    store = SubscriptionStore(config_root())
    try:
        if args.action == "catalog":
            result = catalog()
        elif args.action == "list":
            result = {"subscriptions": store.list_records()}
        elif args.action == "issue":
            result = store.issue(args.tier, customer_label=args.customer)
        else:
            result = store.revoke(args.key_id)
    except SubscriptionError as exc:
        print(f"Phoenix subscription error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.action == "issue":
        print("Store or deliver this key securely; Phoenix will not display it again.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
