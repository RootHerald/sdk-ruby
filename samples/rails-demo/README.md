# Rails demo

Minimal Rails integration for the `rootherald` gem.

## Setup

```bash
bundle add rootherald
```

Copy `config/initializers/rootherald.rb` into your Rails app. Set the
required environment variables (`ROOTHERALD_ISSUER`, optionally
`ROOTHERALD_API_KEY`).

## Controller usage

```ruby
class SignupsController < ApplicationController
  include RootHerald::Guard
  guard_device :create, action: "signup"

  def create
    user = User.create!(device_id: rootherald_claims.device_id)
    render json: { id: user.id }
  end
end
```

Pass `deny_on_warn: true` to `guard_device` to reject WARN verdicts in
addition to DENY.

## Webhook receiver

```ruby
class CaepWebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token  # SET JWT is its own auth

  def receive
    event = RootHerald::Guard.client.verify_set(request.body.read)
    DeviceComplianceJob.perform_later(event.device_id, event.event_payload)
    head :accepted
  rescue RootHerald::WebhookSignatureError
    head :bad_request
  end
end
```
