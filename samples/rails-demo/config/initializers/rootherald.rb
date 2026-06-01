# frozen_string_literal: true

# Place at config/initializers/rootherald.rb in your Rails app.

require "rootherald"

RootHerald::Guard.client = RootHerald::Client.new(
  issuer: ENV.fetch("ROOTHERALD_ISSUER"),
  api_key: ENV["ROOTHERALD_API_KEY"],
  base_url: ENV.fetch("ROOTHERALD_BASE_URL", "https://rootherald.io"),
  jwks_uri: ENV.fetch("ROOTHERALD_JWKS_URI", "https://rootherald.io/.well-known/jwks.json"),
  audience: ENV["ROOTHERALD_AUDIENCE"]
)
