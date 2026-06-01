# frozen_string_literal: true

require "spec_helper"

RSpec.describe RootHerald::JwksFetcher do
  it "caches fetches across calls" do
    calls = 0
    jwks_doc = Fixtures.jwks_document
    fetcher = RootHerald::JwksFetcher.new(
      jwks_uri: Fixtures::JWKS_URI,
      http_fetcher: lambda { |_u|
        calls += 1
        JSON.generate(jwks_doc)
      }
    )
    5.times { fetcher.get_key(Fixtures::KID) }
    expect(calls).to eq(1)
  end

  it "raises JwksError on unknown kid" do
    fetcher = RootHerald::JwksFetcher.new(
      jwks_uri: Fixtures::JWKS_URI,
      cooldown_seconds: 0,
      http_fetcher: ->(_u) { JSON.generate(Fixtures.jwks_document) }
    )
    expect { fetcher.get_key("definitely-not-real") }.to raise_error(RootHerald::JwksError)
  end

  it "wraps HTTP fetch failures" do
    fetcher = RootHerald::JwksFetcher.new(
      jwks_uri: Fixtures::JWKS_URI,
      http_fetcher: ->(_u) { raise "boom" }
    )
    expect { fetcher.get_key(Fixtures::KID) }.to raise_error(RootHerald::JwksError)
  end

  it "rejects malformed JWKS documents" do
    fetcher = RootHerald::JwksFetcher.new(
      jwks_uri: Fixtures::JWKS_URI,
      http_fetcher: ->(_u) { JSON.generate("not_keys" => []) }
    )
    expect { fetcher.get_key(Fixtures::KID) }.to raise_error(RootHerald::JwksError)
  end
end
