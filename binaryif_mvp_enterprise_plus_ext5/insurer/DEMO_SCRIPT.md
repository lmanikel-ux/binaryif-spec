
# BinaryIF — Live Insurer Demo Script (10 minutes)

## Goal
Demonstrate that:
1) A wire cannot execute without a valid Permit.
2) A Permit is cryptographically verifiable and time‑bounded.
3) A Permit is single‑use.
4) Verification can be performed without trusting the runtime system.

## Demo steps
1. Show the control statement:
   "No Permit → No execution."

2. Run conformance:
   - `python tools/conformance_report.py`
   Show: `BINARYIF_CONFORMANCE: PASS`

3. Authorize a wire:
   - Run `python tools/demo_authorize_and_execute.py`
   Show the returned artifact is a PERMIT.

4. Execute the wire (allowed):
   - Demonstrated by the demo script's execution response.

5. Attempt second execution with same Permit (blocked):
   - Re-run execute with same Permit; show denial (single-use).

6. Offline verification:
   - `python verifier/verify.py artifacts/permit.json fixtures/action.json rules/wire_ruleset.json trust/trust_store.json`
   Show: `VALID`

## Stop talking
Once the above is shown, present the underwriting clause and ask:
"Would you be willing to reference a permit requirement like this in coverage language for automated wires?"
