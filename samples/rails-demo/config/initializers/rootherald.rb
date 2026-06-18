# frozen_string_literal: true

# Place at config/initializers/rootherald.rb in your Rails app.

require "rootherald"

# Badge-tier offline verification (the guard middleware). Verifies a
# Root Herald-issued EAT against the JWKS — no secret key involved.
RootHerald::Guard.client = RootHerald::Client.new(
  issuer: ENV.fetch("ROOTHERALD_ISSUER"),
  base_url: ENV.fetch("ROOTHERALD_BASE_URL", "https://rootherald.io"),
  jwks_uri: ENV.fetch("ROOTHERALD_JWKS_URI", "https://rootherald.io/.well-known/jwks.json"),
  audience: ENV["ROOTHERALD_AUDIENCE"]
)

# Background-Check (server -> server) uses ROOTHERALD_SECRET_KEY (rh_sk_…),
# which stays on YOUR server only. See AttestationsController.

