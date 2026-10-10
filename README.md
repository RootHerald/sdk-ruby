# rootherald (Ruby)

Root Herald server SDK for Ruby 3.1+.

Wire 8.0 from `0.7.0`. A 7.0 client cannot enroll against an 8.0 server; see
the [CHANGELOG](CHANGELOG.md) for the migration.

**Backend relay (server → server)** via `RootHerald::Client`: your keyless
client does local TPM work and hands *your* server opaque blobs (no keys, no
Root Herald contact). Your server relays them to Root Herald with your
`rh_sk_` secret key. The verdict is computed by Root Herald and returned to
your backend; it never travels through the client.

```ruby
# Gemfile
gem "rootherald"
```

```bash
gem install rootherald
```

**Three ceremonies, two calls each.**

- `rh.relay_enroll(enroll_request_blob)` / `rh.relay_activate(activation_response)`:
  enroll an installation (`POST /api/v1/attest/enroll`, `/activate`).
- `rh.issue_key_challenge(purpose:, expected_devices:)` /
  `rh.certify_key(certification, nonce:)`: mint a device-bound key
  (`POST /api/v1/keys/challenge`, `/certify`).
- `rh.issue_challenge(ask:, expected_key:, expected_devices:)` /
  `rh.verify(evidence, nonce:, requested_disclosure_class:, expected_key:, expected_devices:)`:
  attest (`POST /api/v1/attest/challenge`, `/verify`).
- `RootHerald::KeySignatures.verify(jwk, message, signature)`: check a
  signature from a certified key locally, with OpenSSL only.

**The challenge carries the ask.** What the device is asked to prove is fixed
when you issue the challenge, bound to it server-side, and echoed to the client
inside the `challenge` string. `verify` appraises against that stored ask, so
nothing between the two calls can widen or weaken it.

## Enroll an installation

Each installation of your client enrolls once. The client's `EnrollBegin`
creates an attestation key (AK) inside the TPM and returns an opaque AK blob
alongside the enroll body; the client keeps the blob and passes it to every
later attest and mint. Windows needs one elevation per enrollment.

```ruby
require "rootherald"

# Construct with your SECRET key (rh_sk_…). Any key without the rh_sk_ prefix
# is rejected.
rh = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

# Leg 1: relay the client's EnrollBegin() blob verbatim. Admission runs under
# the key's identity policy, so a device that could never satisfy it is
# refused before it gets an attestation key (AdmissionRefusedError).
enroll = rh.relay_enroll(enroll_request_blob)
# TPM:   { ekPublicKey:, attestationKey: { publicArea:, parentPublicArea:, qualifiedName: },
#          platform: "windows" | "linux", ekCertPem?:, ekCertificateChain?:, tpmSelfReport?: }
# macOS: { ekPublicKey:, akPublicArea:, platform: "macos" }
# iOS:   { platform: "ios", iosKeyId:, iosAttestationObject:, nonce: }

# Hand enroll.challenge.to_wire ({ enrollmentId:, credentialBlob:,
# encryptedSecret: } for a TPM; { enrollmentId:, challengeNonce: } for macOS)
# to the client's EnrollComplete(), then relay the activation blob it returns.
activation = rh.relay_activate(activation_response) # { enrollmentId:, decryptedSecret: } or { enrollmentId:, signature: }
device_id = activation.device_id
```

`device_id` is your tenant's alias for the device, not a global identifier,
and stays on your server: it is never relayed to the device. A new AK, a new
key, a re-enrollment or a TPM clear never changes it. Bind accounts to it. An
iOS blob enrolls in one leg; its `201` is empty, `enroll.challenge` is `nil`,
and the alias arrives with the first verdict as `result.device_id`.

A flat TPM blob (`akPublicArea` under `platform: "windows"` or `"linux"`) is
the 7.0 shape; `relay_enroll` refuses it with `ArgumentError` before any
request.

When to enroll:

- The client has no AK blob: enroll first.
- The client's attest or mint reports the AK blob unloadable (TPM cleared,
  parent changed): discard the blob, enroll, retry once.
- `verify` answers `enrollment_required: true`: enroll.

## Attest

```ruby
# 1) Mint a challenge; relay challenge.challenge to the client verbatim and
#    keep challenge.nonce, your handle for it.
challenge = rh.issue_challenge(ask: %w[identity posture]) # the default when omitted

# 2) The client quotes over the challenge and returns an opaque evidence blob;
#    submit it for appraisal with the nonce.
result = rh.verify(evidence, nonce: challenge.nonce,
                   requested_disclosure_class: "pseudonymous")     # optional ceiling

proceed_with_signup if result.verdict == :pass

result.device_id             # => the alias (verdict.device.ueid); bind the session to it
result.assurance_claims_met  # => ["urn:rootherald:assurance:…"] satisfied assurance URNs
result.enrollment_required   # => true when the device must enroll first (attest-first)
```

A posture ask runs under the key's posture policy and checks the boot
configuration; use it for step-up.

**Name the device that must answer.** `expected_devices:` takes aliases you
enrolled, `expected_key:` a `key_id` you certified; any other device answers
a failing verdict with reason `expected_device_mismatch`, and an unknown value
is `422 expected_unknown`. Pass the same values to `verify`: the verdict
echoes what the server enforced under `result.expected`, and `verify` refuses
a verdict that does not echo it (`ExpectedNotEnforcedError`).

```ruby
challenge = rh.issue_challenge(ask: %w[identity], expected_devices: [session.device_id])
result = rh.verify(evidence, nonce: challenge.nonce, expected_devices: [session.device_id])
```

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; the resolved policy is pinned on the
challenge when it is minted. Change what a key enforces from the dashboard or
`PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a hand-built
request body is refused with `400 policy_bound_to_key`.

`result.verdict` is the server's own token, `:pass` / `:warn` / `:fail`
(`RootHerald::Verdict::PASS` / `WARN` / `FAIL`, the same vocabulary in every
Root Herald SDK). A response carrying any other token is refused with
`HttpError`, never a guessed verdict. `result.verdict_data` is the full
verdict as the server sent it.

## Device-bound signing keys

A key is created inside the chip and certified by the installation's AK; you
get its public half, the device keeps the blob. A signature on a request then
proves the request came from that device, and you check it with no Root Herald
call.

```ruby
# 1) Mint a key challenge for the device that just passed an attest
#    challenge. Relay kc.key_challenge to the client; keep kc.nonce.
kc = rh.issue_key_challenge(purpose: "sign", expected_devices: [result.device_id])

# 2) The client's MintKey answers with a certification and keeps its key blob.
key = rh.certify_key(certification, nonce: kc.nonce)
store(key.device_id, key.key_id, key.jwk)

# Later, without any Root Herald call: the client signed `message` with its
# key and sent { message, signature }.
jwk = load_device_key(session.device_id)
ok = RootHerald::KeySignatures.verify(jwk, message, signature)
```

`certify_key` returns a `RootHerald::Client::CertifiedKey`:

```ruby
key.device_id      # String  — the alias of the device that holds the key
key.key_id         # String  — Root Herald's id for the key
key.purpose        # "sign" | "decrypt"
key.alg            # "ES256" | "RS256" | "ECDH-ES" | "RSA-OAEP-256"
key.format         # "jwe" | "apple-ecies" | nil — decrypt keys only
key.jwk            # { "kty" => "EC", "crv" => "P-256", "x", "y" } or { "kty" => "RSA", "n", "e" }
key.hardware_bound # false on macOS, where only possession is proved
key.certified_at   # Time
```

Keys are P-256 or RSA-2048, chosen by the device. A signature proves which
chip signed, not how the machine booted; run an attest challenge for that.

Minting again for the same purpose rotates the key under the same `key_id`; a
re-enrolled installation gets new key IDs. The key ID identifies an
installation's credential, never a device: bind accounts to the alias.

`RootHerald::KeySignatures.verify(jwk, message, signature)` takes the message
and the signature as byte strings. ES256: a 64-byte signature is read as raw
`r || s`, any other length as DER. RS256: PKCS#1 v1.5 over SHA-256, exactly
the modulus length (256 bytes). It returns `false` for a malformed or
non-matching signature and raises `ArgumentError` for a JWK it cannot use.

## Errors

An un-enrolled / failing device is a verdict (`:fail`/`:warn`), **not** an
error. Only protocol, auth and budget problems raise, each exposing `status`
and the server's `server_error`:

| Status | Server `error` code                                   | Error                     |
| ------ | ----------------------------------------------------- | ------------------------- |
| 401    | `activation_refused`                                  | `ActivationRefusedError`  |
| 401    | anything else                                         | `InvalidSecretKeyError`   |
| 400    | `invalid_ask`                                         | `InvalidAskError`         |
| 400    | anything else, including `wire_version_unsupported`, `invalid_enroll_shape` | `InvalidEvidenceError` |
| 409    | `key_rotation_conflict`                               | `HttpError`               |
| 409    | anything else                                         | `ChallengeError`          |
| 422    | `unknown_policy`, or none                             | `UnknownPolicyError`      |
| 422    | `admission_refused`                                   | `AdmissionRefusedError`   |
| 422    | `expected_unknown`, `key_disclosure_too_low`          | `HttpError`               |
| 429    | `budget_exhausted`, or an `X-RootHerald-Quota` header | `QuotaExceededError`      |
| 429    | anything else                                         | `RateLimitedError`        |

`ActivationRefusedError` is `relay_activate` being refused for an unknown,
spent or foreign `enrollmentId` or a wrong proof; the secret key was accepted.
`InvalidAskError` is a programming error in your backend, not a device
failure. `RateLimitedError#retry_after_seconds` is the server's `Retry-After`
(else the body's `retryAfterSeconds`, else nil); `QuotaExceededError#budget`
names the budget that refused (`id`, `name`). `UnknownPolicyError` means a
policy bound to the key no longer exists. Any other status, and a 422 or 402
carrying a code no class covers (`posture_not_bound`, `plan_lapsed`), is a
plain `HttpError` with `server_error` preserved. Input the SDK refuses
locally, such as an empty nonce or a 7.0 enroll blob, is `ArgumentError` and
makes no request. `ExpectedNotEnforcedError` is `verify` refusing a verdict
that did not echo the `expected_key` / `expected_devices` the challenge named.

Every request times out after 30 s (`RootHerald::Client::DEFAULT_TIMEOUT_SECONDS`,
the `timeout_seconds:` argument). The default is the same in every Root Herald
server SDK. A custom `http_transport` may return `headers:` (response header
name to value) so the 429 split can read `Retry-After` and
`X-RootHerald-Quota`; the built-in Faraday transport does.

## Rails

`RootHerald::Client` is a plain object — instantiate it in a controller
(or an initializer) and call it from your actions. See
[`samples/rails-demo`](samples/rails-demo) for a full example: `POST
/challenges`, `POST /attestations`, `POST /key-challenges`, `POST /keys` and
`POST /signatures`.
