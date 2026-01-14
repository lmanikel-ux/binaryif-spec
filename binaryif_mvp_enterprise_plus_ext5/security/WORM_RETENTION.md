
# WORM Retention (S3 Object Lock) Guidance

## Goal
Ensure artifact logs cannot be altered or deleted within the retention period.

## AWS S3 Object Lock (recommended)
- Enable Object Lock on the bucket
- Use COMPLIANCE mode for non-bypassable retention
- Apply retention per object (artifact log entries)
- Optional: Legal Hold ON during disputes

## Operational note
WORM is not only about storage; it is about policy enforcement and retention governance.
The MVP provides the interface and backend adapter; production requires IAM and bucket configuration.
