# Changelog

## 0.4.0

### Added

- The challenge carries the ask. `Client#issue_challenge` takes `ask`
  (`Client::ASK_IDENTITY` / `ASK_POSTURE` / `ASK_KEY`), `policy` and
  `key_purpose` beside the existing `device_hint`; `Challenge` gains
  `challenge`, the string to relay to the client verbatim. Omitting `ask`
  keeps the server default of identity + posture.
- `Client::CertifiedKey`; `AttestResult#key` returns the key the appraisal
  certified (`certified_at` is a `Time`), present only on a passing verdict
  for a challenge that asked for `key`.
- `RootHerald::KeySignatures.verify(jwk, message, signature)`: local ECDSA
  verification of device signatures over SHA-256 (P-256) or SHA-384 (P-384)
  with OpenSSL only, accepting raw `r||s` and DER. Returns `false` for any
  malformed signature.
- `Client#relay_enroll(blob, challenge_id: nil)` sends the `challengeId` query
  parameter so admission runs against that challenge's policy;
  `RelayEnrollResult#challenge_id` echoes it when the server does.
- `HttpError#server_error` exposes the server's `error` code. New 422 errors
  keyed on it: `PolicyDowngradeError` (`policy_downgrade`) and
  `AdmissionRefusedError` (`admission_refused`). Other 422s remain
  `UnknownPolicyError`.

### Fixed

- The README sentence about the ABI 2.0 names was cut off mid-thought; it is
  replaced by the ask and key documentation.
- `samples/rails-demo` now shows the challenge, attest and signature routes.
