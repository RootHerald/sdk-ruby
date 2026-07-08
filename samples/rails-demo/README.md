# Rails demo

Minimal Rails integration for the `rootherald` gem.

## Setup

```bash
bundle add rootherald
```

Copy `config/initializers/rootherald.rb` into your Rails app. Set the
`ROOTHERALD_SECRET_KEY` (rh_sk_…) environment variable — it stays on your
server only.

## Controller usage (Background-Check, server → server)

The dumb client POSTs its opaque evidence blob to your server; your server
appraises it with Root Herald using the `rh_sk_` secret key.

```ruby
class AttestationsController < ApplicationController
  RH = RootHerald::BackgroundCheck.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

  def create
    challenge = RH.issue_challenge
    result = RH.verify(params.require(:evidence).to_unsafe_h,
                       challenge_id: challenge.challenge_id)

    if result.verdict == :allow
      render json: { ok: true, verdict: result.verdict }
    else
      # An un-enrolled / failing device is a verdict, not an error.
      render json: { ok: false, verdict: result.verdict }, status: :forbidden
    end
  end
end
```
