# frozen_string_literal: true

# Server -> server flow with a device-bound signing key. The keyless client
# POSTs its opaque blobs to YOUR server; your server relays them to Root Herald
# with the rh_sk_ secret key. The client never holds a key or calls Root Herald
# directly.
#
#   post "/challenges",     to: "attestations#challenge"
#   post "/attestations",   to: "attestations#create"
#   post "/key-challenges", to: "attestations#key_challenge"
#   post "/keys",           to: "attestations#certify"
#   post "/signatures",     to: "attestations#verify_signature"
class AttestationsController < ApplicationController
  # Configured once in config/initializers/rootherald.rb (see RH below).
  RH = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

  # 1) Mint a challenge that carries the ask and hand `challenge` to the client
  #    verbatim. `nonce` is the handle the evidence comes back with. What the
  #    device must prove is fixed here, not at verify time.
  def challenge
    c = RH.issue_challenge(ask: [RootHerald::Client::ASK_IDENTITY, RootHerald::Client::ASK_POSTURE])
    render json: { nonce: c.nonce, challenge: c.challenge, expiresAt: c.expires_at }
  end

  # 2) The client quoted over the challenge and posts its opaque evidence here
  #    with the nonce; appraise it with the rh_sk_ secret key.
  def create
    result = RH.verify(params.require(:evidence).to_unsafe_h,
                       nonce: params.require(:nonce))

    if result.verdict == :pass
      # The alias is the device's only identity; bind the session to it.
      session[:device_id] = result.device_id
      render json: { ok: true, verdict: result.verdict }
    else
      # An un-enrolled / failing device is a verdict, not an error.
      render json: { ok: false, verdict: result.verdict }, status: :forbidden
    end
  end

  # 3) Mint a key challenge for the device that just passed; hand
  #    `keyChallenge` to the client's MintKey verbatim and keep `nonce`.
  def key_challenge
    kc = RH.issue_key_challenge(purpose: RootHerald::Client::KEY_PURPOSE_SIGN,
                                expected_devices: [session.fetch(:device_id)])
    render json: { nonce: kc.nonce, keyChallenge: kc.key_challenge, expiresAt: kc.expires_at }
  end

  # 4) Relay the client's certification; store the public half against the
  #    device. A real app stores it against the user; the Rails cache stands
  #    in here.
  def certify
    key = RH.certify_key(params.require(:certification).to_unsafe_h,
                         nonce: params.require(:nonce))
    Rails.cache.write("rootherald:key:#{key.device_id}", key.jwk)
    render json: { ok: true, keyId: key.key_id, deviceId: key.device_id }
  end

  # 5) Later, the device signs something with its key. Check it against the
  #    stored JWK locally, no Root Herald call. `message` and `signature` are
  #    base64; an ES256 signature may be raw r||s or DER.
  def verify_signature
    jwk = Rails.cache.read("rootherald:key:#{session.fetch(:device_id)}")
    return render json: { error: "no key for this device" }, status: :not_found unless jwk

    valid = RootHerald::KeySignatures.verify(
      jwk,
      params.require(:message).unpack1("m0"),
      params.require(:signature).unpack1("m0")
    )
    render json: { valid: valid }, status: valid ? :ok : :forbidden
  end
end
