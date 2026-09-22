# 0003: Limit detection scope to keyword matching, excluding value-shape-based detection

[← Back to ADR index](List-Of-ADR.md)

## Status

Accepted

## Background

While replacing betterleaks with a self-contained scanner in
[0002](0002-replace-betterleaks.md), how far to build out the detection
method became a point of discussion. betterleaks judged not only by
"key-name clues" but also by "value shape." Concretely:

- Detecting PEM / OpenSSH private-key blocks (a multi-line finding for
  `-----BEGIN RSA PRIVATE KEY-----`).
- Extracting credentials embedded in a URL like `redis://:PASSWORD@host`,
  based purely on the **shape of the password portion**, independent of the
  key name (`redis.url`).
- Detecting service-specific token shapes for AWS / GitHub / Slack /
  Stripe, etc.

Adopting the new approach as-is (judging by whether the key name contains a
filter word like `password` / `apikey` / `secret`) would mean these
"shape-based" detections could no longer be covered. Existing tests and
fixtures (the redis-URL assertion and the multi-line PEM assertion in
`app.properties`, etc.) also depended on this capability.

## Options considered

1. **Limit to keyword matching only**: as specified, detect only `key=value`
   / XML attributes / JSON based on the key name. PEM blocks and
   URL-embedded credentials go out of scope, and existing fixtures/tests are
   rewritten to match the new approach.
2. **Keyword matching + additional structural rules**: on top of basic
   keyword matching, implement dedicated rules for detecting URL credentials
   in the `scheme://user:PASSWORD@host` form and PEM/SSH private-key blocks,
   preserving as much of the intent of the existing tests as possible.

## Decision

Adopted option 1 (limit to keyword matching only).

Reasoning: the original motivation ([0002](0002-replace-betterleaks.md)) was
that "masking gaps were too easy to hit relative to the adoption cost."
Heuristics based on value shape inherently carry this same problem
(betterleaks itself failed to detect AWS keys containing `DUMMY`). Judging
purely by key-name match lets us narrow the guarantee to something simple
and explainable: "a value whose key name matches this will always be
masked." The more structural rules we add, the more the detection logic
itself re-inherits the same problem — passing through silently when a value's
shape doesn't match.

## Consequences

- **Detection capability lost** (also documented in README.md's "Known
  limitations"):
  - Credentials embedded in a URL (e.g. `redis.url=redis://:PASS@host`,
    where the key name gives no clue).
  - Items whose value is a PEM / OpenSSH private-key block
    (`tls.private_key=-----BEGIN ...`). Note that the key **files**
    themselves (`*.pem` / `*.key`, etc.) are still in scope via
    `always_target_globs` — but since their content is judged the same
    key-name-based way, they go undetected if no `key=value` inside them
    matches.
  - Tokens whose name contains no `filter_words` (`github.token`,
    `aws.access_key_id`, `slack.bot_token`, etc.). Handle these individually
    by adding words to `filter_words` if needed.
- **Partial mitigation**: if a detected secret's value appears again
  elsewhere in the file with no key-name clue, a second-pass "residual
  cleanup" scrubs that occurrence too (limited to values at least
  `min_scrub_len` long). For example, if the same string as `app.password`'s
  value is embedded in `service.url`, and it was detected on the
  `app.password` side, the `service.url` side gets scrubbed as well.
- From the existing fixture (`app.properties`) and demo file
  (`sample-secrets.properties`), we removed entries with no filter word in
  the key name — covering AWS/GCP/Azure/Stripe/GitHub/GitLab/npm/Slack/
  Discord/Twilio/SendGrid/Datadog/newrelic/Cloudflare/Firebase,
  PEM/OpenSSH private-key blocks, and redis/mongodb URL-embedded
  credentials — keeping only entries detectable by keyword matching.
