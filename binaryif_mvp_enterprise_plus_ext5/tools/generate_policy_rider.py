
import argparse

TEMPLATE = """Automated Irreversible Action Authorization Clause

Coverage for automated or system-initiated {action_desc} in excess of {currency} {threshold} applies only where such action was executed pursuant to a valid BinaryIF Authorization Permit issued prior to execution.

A BinaryIF Authorization Permit is a cryptographically verifiable authorization record bound to the specific action parameters, the ruleset in force, and a defined time window (TTL <= {ttl_seconds}s).

Absence of a valid BinaryIF Authorization Permit at the time of execution constitutes unauthorized execution for purposes of coverage determination.
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, required=True)
    ap.add_argument("--currency", type=str, default="USD")
    ap.add_argument("--ttl", type=int, default=300)
    ap.add_argument("--action", type=str, default="wire_transfer")
    args = ap.parse_args()

    action_desc = "funds transfers" if args.action == "wire_transfer" else args.action.replace("_"," ")
    print(TEMPLATE.format(action_desc=action_desc, currency=args.currency, threshold=args.threshold, ttl_seconds=args.ttl))

if __name__ == "__main__":
    main()
