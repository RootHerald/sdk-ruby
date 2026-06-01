# Root Herald — Ruby SDK

Backend SDK for verifying [Root Herald](https://rootherald.io) device attestation JWTs from Ruby applications. Plain Ruby + Rails-friendly.

## Install

```ruby
# Gemfile
gem 'rootherald'
```

```bash
bundle install
```

Requires Ruby 3.1 or later.

## 30-second integration

```ruby
require 'rootherald'

client = RootHerald::Client.new(
  issuer: 'https://api.rootherald.io',
  audience: 'plat_your_client_id',
)

verdict = client.verify_token(request.headers['Authorization'])

unless verdict.device.verdict == 'pass'
  return render status: :forbidden, json: { error: 'device_check_failed' }
end

render json: { device: verdict.device.device_id }
```

## Rails integration

```ruby
# config/initializers/rootherald.rb
RootHerald.configure do |c|
  c.issuer = ENV.fetch('ROOTHERALD_ISSUER')
  c.audience = ENV.fetch('ROOTHERALD_AUDIENCE')
end

# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include RootHerald::Guard

  before_action :guard_device, only: [:create, :update]
end
```

## What you get

- `RootHerald::Client` — JWKS-cached token verifier
- `RootHerald::Guard` mixin for controllers
- Strongly-typed `Verdict` + `DeviceVerdict` value objects
- `WebhookVerifier` for CAEP webhook signature checks

## Trust chain

The SDK fetches Root Herald's signing keys from `{issuer}/.well-known/jwks.json` and caches them in memory. Token signature verification happens locally after the first JWKS fetch.

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
