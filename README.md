# rootherald (Ruby)

Root Herald server SDK for Ruby 3.1+. Two paths:

- **Background-Check (server → server)** via `RootHerald::BackgroundCheck`: your
  dumb client collects an opaque evidence blob and hands it to *your* server,
  which appraises it with Root Herald using your `rh_sk_` secret key. The client
  never holds a key or talks to Root Herald.
- **Badge tier (offline verify)** via `RootHerald::Client#verify_token` + the Rails
  guard: verify a Root Herald-issued EAT (JWT) and CAEP webhook events against
  the JWKS.

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

# Construct with your SECRET key (rh_sk_…). A publishable key (rh_pk_…) is
# rejected — it must never be used server-side.
rh = RootHerald::BackgroundCheck.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

# 1) Mint a relay-friendly nonce; send challenge.nonce down to the client.
challenge = rh.issue_challenge

# 2) The client quotes over the nonce and returns an opaque evidence blob;
#    submit it for appraisal.
result = rh.verify(evidence, challenge_id: challenge.challenge_id,
                   policy: "rootherald:builtin:strict-hardware", # optional
                   return_token: true)                           # optional EAT

proceed_with_signup if result.verdict == :allow
```

> `issue_challenge`/`verify` are the ABI 2.0 names; the previous
> `create_challenge`/`attest` remain as deprecated aliases.

### One-time device enroll (relay)

The keyless client produces opaque enroll blobs; your backend relays them with
the `rh_sk_` secret. The enroll endpoint is asymmetric: a fresh device returns
a MakeCredential challenge (`201`); an already-bound device short-circuits
(`409`), in which case you **skip** the activate leg.

```ruby
# 1) Relay the client's EnrollBegin() blob (opaque, passed through verbatim).
enroll = rh.relay_enroll(enroll_request_blob) # { ekPublicKey:, akPublicArea:, platform:, ekCertPem?:, ekCertificateChain?: }

if enroll.already_enrolled?
  device_id = enroll.device_id           # already bound — done
else
  # 2) Hand enroll.challenge (credential_blob/encrypted_secret) to the client's
  #    EnrollComplete(), then relay the activation blob it returns.
  activation = rh.relay_activate(activation_response) # { deviceId:, decryptedSecret:, akPublicKey?: }
  device_id = activation.device_id
end
```

An un-enrolled / failing device is a verdict (`:deny`/`:warn`), **not** an
error. Only protocol/auth/quota problems raise: `InvalidSecretKeyError` (401),
`UnknownPolicyError` (422), `ChallengeError` (409), `InvalidEvidenceError`
(400), `QuotaExceededError` (429).

## Verify a token (badge tier)

```ruby
require "rootherald"

client = RootHerald::Client.new(
  issuer: "https://rootherald.io/myorg",
  jwks_uri: "https://rootherald.io/.well-known/jwks.json"
)
claims = client.verify_token(token)
proceed_with_signup if claims.allow?
```

## Rails

```ruby
# config/initializers/rootherald.rb
RootHerald::Guard.client = RootHerald::Client.new(issuer: ENV.fetch("ROOTHERALD_ISSUER"))

# app/controllers/signups_controller.rb
class SignupsController < ApplicationController
  include RootHerald::Guard
  guard_device :create, action: "signup"

  def create
    # rootherald_claims is available here
  end
end
```

See [`samples/rails-demo`](samples/rails-demo) for a full example, including
the CAEP webhook receiver.
