# Rails demo

Minimal Rails integration for the `rootherald` gem.

## Setup

```bash
bundle add rootherald
```

Copy `config/initializers/rootherald.rb` into your Rails app. Set the
`ROOTHERALD_SECRET_KEY` (rh_sk_…) environment variable — it stays on your
server only.

## Controller usage (server → server, with a device-bound signing key)

The keyless client POSTs its opaque blobs to your server; your server relays
them to Root Herald using the `rh_sk_` secret key. Five actions, routed as:

```ruby
post "/challenges",     to: "attestations#challenge"
post "/attestations",   to: "attestations#create"
post "/key-challenges", to: "attestations#key_challenge"
post "/keys",           to: "attestations#certify"
post "/signatures",     to: "attestations#verify_signature"
```

```ruby
class AttestationsController < ApplicationController
  RH = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

  # 1) Mint a challenge that carries the ask; relay `challenge` to the client.
  def challenge
    c = RH.issue_challenge(ask: %w[identity posture])
    render json: { nonce: c.nonce, challenge: c.challenge, expiresAt: c.expires_at }
  end

  # 2) Appraise the evidence the client produced; bind the session to the alias.
  def create
    result = RH.verify(params.require(:evidence).to_unsafe_h,
                       nonce: params.require(:nonce))

    if result.verdict == :pass
      session[:device_id] = result.device_id
      render json: { ok: true, verdict: result.verdict }
    else
      # An un-enrolled / failing device is a verdict, not an error.
      render json: { ok: false, verdict: result.verdict }, status: :forbidden
    end
  end

  # 3) Mint a key challenge for that device; relay `keyChallenge` to the client.
  def key_challenge
    kc = RH.issue_key_challenge(purpose: "sign", expected_devices: [session.fetch(:device_id)])
    render json: { nonce: kc.nonce, keyChallenge: kc.key_challenge, expiresAt: kc.expires_at }
  end

  # 4) Relay the client's certification; store the public half.
  def certify
    key = RH.certify_key(params.require(:certification).to_unsafe_h,
                         nonce: params.require(:nonce))
    Rails.cache.write("rootherald:key:#{key.device_id}", key.jwk)
    render json: { ok: true, keyId: key.key_id, deviceId: key.device_id }
  end

  # 5) Check a later signature from the device against the stored key, locally.
  def verify_signature
    jwk = Rails.cache.read("rootherald:key:#{session.fetch(:device_id)}")
    return render json: { error: "no key for this device" }, status: :not_found unless jwk

    valid = RootHerald::KeySignatures.verify(jwk,
                                             params.require(:message).unpack1("m0"),
                                             params.require(:signature).unpack1("m0"))
    render json: { valid: valid }, status: valid ? :ok : :forbidden
  end
end
```
