# rootherald (Ruby)

Root Herald server SDK for Ruby 3.1+. Verifies attestation token JWTs
and CAEP webhook events (SET JWTs) against the Root Herald JWKS.
Pure Ruby — depends only on `jwt` and `faraday`.

```bash
gem install rootherald
```

or in your `Gemfile`:

```ruby
gem "rootherald"
```

## Usage

```ruby
require "rootherald"

client = RootHerald::Client.new(
  issuer: "https://rootherald.io/myorg",
  jwks_uri: "https://rootherald.io/.well-known/jwks.json"
)
claims = client.verify_token(token)
proceed_with_signup if claims.verdict == RootHerald::Verdict::ALLOW
```

`claims` exposes:

- `claims.subject` — stable user UUID
- `claims.acr`, `claims.amr`, `claims.auth_time` — OIDC claims
- `claims.device_id` — `rootherald_device.ueid`
- `claims.tpm_class`, `claims.platform`, `claims.attestation_type`
- `claims.ear_status` and `claims.verdict` (`:allow` / `:warn` / `:deny`)
- `claims.allow?`, `claims.warn?`, `claims.deny?` — convenience predicates
- `claims.raw` — the verified payload hash

## Webhook verification

```ruby
event = client.verify_set(request.body.read)

if event.event_type == "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
  Devices.update(event.device_id, event.event_payload)
end
```

## Rails integration

```ruby
# config/initializers/rootherald.rb
RootHerald::Guard.client = RootHerald::Client.new(
  issuer: ENV.fetch("ROOTHERALD_ISSUER")
)

# app/controllers/signups_controller.rb
class SignupsController < ApplicationController
  include RootHerald::Guard
  guard_device :create, action: "signup"

  def create
    # rootherald_claims is available here
  end
end
```

Pass `deny_on_warn: true` to `guard_device` to reject WARN verdicts.

## Errors

All errors inherit from `RootHerald::Error`:

- `TokenExpiredError` — `exp` claim is in the past
- `VerificationError` — signature / issuer / audience / schema failure
- `WebhookSignatureError` — SET JWT failed verification
- `JwksError` — JWKS could not be fetched / parsed
- `HttpError` — Root Herald REST API returned non-2xx

## Tests

```bash
bundle install
bundle exec rspec
```

## Build the gem

```bash
gem build rootherald.gemspec
```
