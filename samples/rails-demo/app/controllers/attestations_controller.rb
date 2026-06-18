# frozen_string_literal: true

# Background-Check (server -> server). The dumb client POSTs its opaque evidence
# blob to YOUR server; your server appraises it with Root Herald using the
# rh_sk_ secret key. The client never holds a key or calls Root Herald directly.
class AttestationsController < ApplicationController
  # Configured once in config/initializers/rootherald.rb (see RH below).
  RH = RootHerald::BackgroundCheck.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

  def create
    # 1) mint a nonce; in production, hand challenge.nonce to the client first,
    #    then receive the evidence it produced. Compressed here.
    challenge = RH.create_challenge

    # 2) appraise the opaque evidence the client posted.
    result = RH.attest(params.require(:evidence).to_unsafe_h,
                       challenge_id: challenge.challenge_id)

    if result.verdict == :allow
      render json: { ok: true, verdict: result.verdict }
    else
      # An un-enrolled / failing device is a verdict, not an error.
      render json: { ok: false, verdict: result.verdict }, status: :forbidden
    end
  end
end
