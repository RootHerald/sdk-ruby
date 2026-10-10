# Changelog

## 0.7.0

Wire 8.0. Every installation of a client has its own attestation key, created
inside the TPM at enrollment and handed back as an opaque AK blob the client
keeps and passes to every attest and mint. Keys are minted in their own
ceremony. A backend on this version cannot drive a 7.0 client, and the
reverse; the server refuses a 7.0-shaped enroll body with
`400 wire_version_unsupported`.

### Breaking

- `Client#relay_enroll` takes the 8.0 TPM body `{ ekPublicKey, attestationKey:
  { publicArea, parentPublicArea, qualifiedName }, platform, … }` and refuses
  a flat `akPublicArea` TPM body locally (`ArgumentError`). `platform` is
  required. The macOS body stays flat and the iOS body is unchanged; every
  body is relayed verbatim, unknown fields included.
- Keys are minted by `Client#issue_key_challenge(purpose:, expected_devices:)`
  → `KeyChallenge` and `Client#certify_key(certification, nonce:)` →
  `CertifiedKey` (`device_id`, `key_id`, `purpose`, `alg`, `format`, `jwk`,
  `hardware_bound`, `certified_at`). `Client::ASK_KEY`, the `key_purpose:`
  keyword, `AttestResult#key` and `CertifiedKey#auth_policy` are removed; a
  challenge that still asks for `"key"` is `InvalidAskError`
  (400 `invalid_ask`).
- `Client#issue_challenge` takes `expected_key:` and `expected_devices:`;
  the `device_hint:` keyword is gone and passing it raises `ArgumentError`.
  Pass the same values to `Client#verify`: a verdict that does not echo them
  under `expected` is refused with `ExpectedNotEnforcedError`.
- `CertifiedKey#jwk` is an EC P-256 or an RSA JWK, chosen by the device;
  `KeySignatures.verify` and `certify_key` accept RSA-2048 keys (RS256,
  PKCS#1 v1.5). P-384 is no longer accepted: no device certifies one.
- A 429 `budget_exhausted` is `QuotaExceededError` with `#budget` (`id`,
  `name`); the `quota_exceeded` code is gone. A 409 `key_rotation_conflict`
  is a plain `HttpError`, not `ChallengeError`. A 400 `invalid_purpose` is
  `InvalidAskError` (`server_error` carries the code); a 400
  `invalid_certification` is `InvalidEvidenceError`; a 422
  `purpose_unsupported` or `certification_rejected` is a plain `HttpError`.
- `Verdict` is the server's own token: `:pass` / `:warn` / `:fail`
  (`Verdict::PASS` / `WARN` / `FAIL`) replace `:allow` / `:warn` / `:deny`,
  the same vocabulary as every other Root Herald SDK. `Verdict.from_raw`
  returns nil for any other token and `Client#verify` then raises
  `HttpError` instead of reading it as `:warn`; `Verdict.from_ear_status` is
  removed.
- An empty `nonce:` on `Client#verify` raises `ArgumentError`, not
  `ChallengeError`; no request is made.
- A 401 carrying `activation_refused` is `ActivationRefusedError`, not
  `InvalidSecretKeyError`. A 429 without a budget signal is
  `RateLimitedError`, with `retry_after_seconds`, not `QuotaExceededError`.
  A 422 whose code is neither `unknown_policy` nor `admission_refused`
  (`posture_not_bound`, `expected_unknown`, `key_disclosure_too_low`) is a
  plain `HttpError` with the code preserved.
- The default timeout is 30 s (`Client::DEFAULT_TIMEOUT_SECONDS`), was 10 s.
- An `http_transport` may return `headers:` alongside `status:` and `body:`;
  the built-in Faraday transport does.

### Added

- `AttestResult#device_id` (`verdict.device.ueid`) and `AttestResult#expected`.

### Migration

1. Re-enroll every installation: the client's `EnrollBegin` now returns an
   AK blob, which the client keeps and passes to `Attest` and `MintKey`.
2. Replace `issue_challenge(ask: %w[identity key], key_purpose: "sign")` plus
   `result.key` with `issue_key_challenge(purpose: "sign", expected_devices:
   [alias])` and `certify_key(certification, nonce:)`.
3. Drop `device_hint:`; bind a challenge to a device with `expected_devices:`.

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
