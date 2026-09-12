# Changelog

## 0.6.0

### Breaking

- Wire 7.0: nothing a client sends locates a row. `Challenge` is `nonce` /
  `challenge` / `expires_at`; `challenge_id` is gone. `Client#verify` takes
  `nonce:` (the handle from `issue_challenge`, the second segment of the
  challenge string) and sends it as `nonce`; a missing one raises
  `ChallengeError` as a missing `challenge_id` did.
- `Client#relay_enroll(blob)` takes no `challenge_id:` and sends no query
  string. It returns `RelayEnrollResult#challenge` only: an `EnrollChallenge`
  of `enrollment_id` plus `credential_blob` / `encrypted_secret` (TPM) or
  `challenge_nonce` (macOS), whose `#to_wire` is the camelCase body to hand to
  the client's `EnrollComplete`. `RelayEnrollResult#device_id` and
  `#challenge_id` are gone; the alias comes from `relay_activate`. An iOS blob
  (`platform: "ios"` with `iosKeyId` / `iosAttestationObject` / `nonce`) is
  accepted and its empty `201` yields `challenge: nil`.
- `Client#relay_activate` requires `enrollmentId` plus `decryptedSecret` (TPM)
  or `signature` (macOS); `deviceId` and `akPublicKey` are no longer read.
  `ActivateResult` is unchanged.

## 0.5.0

### Breaking

- Policies bind to API keys. The `policy` keyword is gone from
  `Client#issue_challenge` and `Client#verify`, and the request bodies no
  longer carry a `policy` field. The server refuses the field with
  `400 policy_bound_to_key`. Bind a policy to the key from the dashboard or
  `PUT /api/v1/admin/api-keys/{id}/policies`; the resolved policy is pinned
  on the challenge at mint.
- `PolicyDowngradeError` is removed with the field that produced it.
  `UnknownPolicyError` (422 `unknown_policy`) now means a policy bound to the
  key no longer exists; nothing is substituted.
- `Client#relay_enroll(blob, challenge_id: nil)` is unchanged on the wire;
  admission runs under the identity policy bound to the key, pinned on the
  challenge when one is passed.

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
