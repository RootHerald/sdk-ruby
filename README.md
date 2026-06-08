# rootherald (Ruby)

Root Herald server SDK for Ruby 3.1+. Verifies attestation token JWTs
and CAEP webhook events (SET JWTs) against the Root Herald JWKS.

```ruby
# Gemfile
gem "rootherald"
```

```bash
gem install rootherald
```

## Verify a token

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
