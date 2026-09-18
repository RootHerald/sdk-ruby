# rootherald (Ruby)

Root Herald server SDK for Ruby 3.1+.

**Background-Check (server → server)** via `RootHerald::Client`: your
dumb client collects an opaque evidence blob and hands it to *your* server,
which appraises it with Root Herald using your `rh_sk_` secret key. The client
never holds a key or talks to Root Herald.

```ruby
# Gemfile
gem "rootherald"
```

```bash
gem install rootherald
```

## Background-Check (server → server)

```ruby
require "rootherald"

# Construct with your SECRET key (rh_sk_…). Any key without the rh_sk_ prefix
# is rejected.
rh = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

# 1) Mint a challenge; relay challenge.challenge to the client verbatim and
#    keep challenge.nonce, your handle for it. The challenge carries the ask:
#    what the device must prove is fixed here.
challenge = rh.issue_challenge(ask: %w[identity posture]) # the default when omitted

# 2) The client quotes over the challenge and returns an opaque evidence blob;
#    submit it for appraisal with the nonce.
result = rh.verify(evidence, nonce: challenge.nonce,
                   requested_disclosure_class: "pseudonymous")     # optional ceiling

proceed_with_signup if result.verdict == :pass

result.assurance_claims_met  # => ["urn:rootherald:assurance:…"] satisfied assurance URNs
result.enrollment_required   # => true when the device must enroll first (attest-first)
```

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; a posture ask runs under the posture
policy and everything else under the identity policy. The resolved policy is
pinned on the challenge when it is minted. Change what a key enforces from the
dashboard or `PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a
hand-built request body is refused with `400 policy_bound_to_key`.

### Certified device key

Ask for `key` and a passing verdict also certifies a fresh TPM-resident P-256
signing key. Store `result.key` against the user; later signatures from the
device verify locally, with no Root Herald call.

```ruby
challenge = rh.issue_challenge(ask: %w[identity key], key_purpose: "sign")
result = rh.verify(evidence, nonce: challenge.nonce)
key = result.key                      # present only on a pass with a key ask
store(user_id, key.key_id, key.jwk)

# Later: the device signed `message` with that key (raw r||s or DER).
ok = RootHerald::KeySignatures.verify(key.jwk, message, signature)
```

### One-time device enroll (relay)

The keyless client produces opaque enroll blobs; your backend relays them with
the `rh_sk_` secret. Every enrollment returns an activation challenge, a
device already known included — re-enrollment is how a device rotates its
attestation key. Nothing in either blob names the device: the server resolves
the enrollment from the `enrollmentId` it minted.

```ruby
# 1) Relay the client's EnrollBegin() blob (opaque, passed through verbatim).
#    Admission runs under the key's identity policy; a device that could never
#    satisfy it is refused with AdmissionRefusedError.
enroll = rh.relay_enroll(enroll_request_blob) # { ekPublicKey:, akPublicArea:, platform:, ekCertPem?:, ekCertificateChain?: }

# 2) Hand enroll.challenge.to_wire ({ enrollmentId:, credentialBlob:,
#    encryptedSecret: } for a TPM; { enrollmentId:, challengeNonce: } for macOS)
#    to the client's EnrollComplete(), then relay the activation blob it returns.
activation = rh.relay_activate(activation_response) # { enrollmentId:, decryptedSecret: } or { enrollmentId:, signature: }
device_id = activation.device_id
```

`device_id` is your tenant's alias for the device, not a global identifier,
and stays on your server: it is never relayed to the device. An iOS blob
(`platform: "ios"`) enrolls in one leg; its `201` is empty, `enroll.challenge`
is `nil`, and the alias arrives with the first verdict as `verdict.device.ueid`.

`result.verdict` is the server's own token, `:pass` / `:warn` / `:fail`
(`RootHerald::Verdict::PASS` / `WARN` / `FAIL`, the same vocabulary in every
Root Herald SDK). A response carrying any other token is refused with
`HttpError`, never a guessed verdict.

## Errors

An un-enrolled / failing device is a verdict (`:fail`/`:warn`), **not** an
error. Only protocol, auth and quota problems raise, each exposing `status`
and the server's `server_error`:

| Status | Server `error` code                                 | Error                    |
| ------ | --------------------------------------------------- | ------------------------ |
| 401    | `activation_refused`                                | `ActivationRefusedError` |
| 401    | anything else                                       | `InvalidSecretKeyError`  |
| 400    |                                                     | `InvalidEvidenceError`   |
| 409    |                                                     | `ChallengeError`         |
| 422    | `unknown_policy`, or none                           | `UnknownPolicyError`     |
| 422    | `admission_refused`                                 | `AdmissionRefusedError`  |
| 429    | `quota_exceeded`, or an `X-RootHerald-Quota` header | `QuotaExceededError`     |
| 429    | anything else                                       | `RateLimitedError`       |

`ActivationRefusedError` is `relay_activate` being refused for an unknown,
spent or foreign `enrollmentId` or a wrong proof; the secret key was accepted.
`RateLimitedError#retry_after_seconds` is the server's `Retry-After` (else the
body's `retryAfterSeconds`, else nil); `QuotaExceededError` is the metered
billing ceiling. `UnknownPolicyError` means a policy bound to the key no
longer exists. Any other status, and a 422 or 402 carrying a code no class
covers (`posture_not_bound`, `plan_lapsed`), is a plain `HttpError` with
`server_error` preserved. Input the SDK refuses locally, such as an empty
nonce, is `ArgumentError` and makes no request.

Every request times out after 30 s (`RootHerald::Client::DEFAULT_TIMEOUT_SECONDS`,
the `timeout_seconds:` argument). The default is the same in every Root Herald
server SDK. A custom `http_transport` may return `headers:` (response header
name to value) so the 429 split can read `Retry-After` and
`X-RootHerald-Quota`; the built-in Faraday transport does.

## Rails

`RootHerald::Client` is a plain object — instantiate it in a controller
(or an initializer) and call it from your actions. See
[`samples/rails-demo`](samples/rails-demo) for a full example: `POST
/challenges`, `POST /attestations` and `POST /signatures`.
