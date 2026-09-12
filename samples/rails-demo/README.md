# Rails demo

Minimal Rails integration for the `rootherald` gem.

## Setup

```bash
bundle add rootherald
```

Copy `config/initializers/rootherald.rb` into your Rails app. Set the
`ROOTHERALD_SECRET_KEY` (rh_sk_…) environment variable — it stays on your
server only.

## Controller usage (server → server, with a certified device key)

The dumb client POSTs its opaque evidence blob to your server; your server
appraises it with Root Herald using the `rh_sk_` secret key. Three actions,
routed as:

```ruby
post "/challenges",   to: "attestations#challenge"
post "/attestations", to: "attestations#create"
post "/signatures",   to: "attestations#verify_signature"
```

```ruby
class AttestationsController < ApplicationController
  RH = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

  # 1) Mint a challenge that carries the ask; relay `challenge` to the client.
  def challenge
    c = RH.issue_challenge(ask: %w[identity posture key], key_purpose: "sign")
    render json: { nonce: c.nonce, challenge: c.challenge, expiresAt: c.expires_at }
  end

  # 2) Appraise the evidence the client produced; keep the certified key on a pass.
  def create
    result = RH.verify(params.require(:evidence).to_unsafe_h,
                       nonce: params.require(:nonce))

    if result.verdict == :allow
      key = result.key # present only on a pass for a challenge that asked for one
      Rails.cache.write("rootherald:key:#{key.key_id}", key.jwk) if key
      render json: { ok: true, verdict: result.verdict, keyId: key&.key_id }
    else
      # An un-enrolled / failing device is a verdict, not an error.
      render json: { ok: false, verdict: result.verdict }, status: :forbidden
    end
  end

  # 3) Check a later signature from the device against the stored key, locally.
  def verify_signature
    jwk = Rails.cache.read("rootherald:key:#{params.require(:keyId)}")
    return render json: { error: "unknown keyId" }, status: :not_found unless jwk

    valid = RootHerald::KeySignatures.verify(jwk,
                                             params.require(:message).unpack1("m0"),
                                             params.require(:signature).unpack1("m0"))
    render json: { valid: valid }, status: valid ? :ok : :forbidden
  end
end
```
