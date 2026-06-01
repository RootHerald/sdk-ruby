# frozen_string_literal: true

require "spec_helper"

RSpec.describe RootHerald::WebhookVerifier do
  def verifier(audience: nil)
    RootHerald::WebhookVerifier.new(
      issuer: Fixtures::ISSUER,
      jwks: Fixtures.jwks_fetcher,
      audience: audience
    )
  end

  it "decodes a valid SET into a WebhookEvent" do
    event = verifier.verify_set(Fixtures.make_set)
    expect(event.issuer).to eq(Fixtures::ISSUER)
    expect(event.device_id).to eq("device-uuid-1234")
    expect(event.event_type).to start_with("https://schemas.openid.net/secevent/caep/")
    expect(event.event_payload).to include("current_status")
  end

  it "rejects SETs with typ != secevent+jwt" do
    expect do
      verifier.verify_set(Fixtures.make_set(typ: "JWT"))
    end.to raise_error(RootHerald::WebhookSignatureError)
  end

  it "rejects non-compact-JWT bodies" do
    expect { verifier.verify_set("not.a.jwt.body") }.to raise_error(RootHerald::WebhookSignatureError)
  end

  it "rejects empty bodies" do
    expect { verifier.verify_set("") }.to raise_error(RootHerald::WebhookSignatureError)
  end

  it "rejects mismatched issuer" do
    expect do
      verifier.verify_set(Fixtures.make_set(issuer: "https://attacker.example/myorg"))
    end.to raise_error(RootHerald::WebhookSignatureError)
  end

  it "validates audience when configured" do
    event = verifier(audience: "my-stream").verify_set(Fixtures.make_set(audience: "my-stream"))
    expect(event.audience).to eq("my-stream")
  end

  it "rejects wrong audience" do
    expect do
      verifier(audience: "my-stream").verify_set(Fixtures.make_set(audience: "other"))
    end.to raise_error(RootHerald::WebhookSignatureError)
  end

  it "rejects tampered signatures" do
    body = Fixtures.make_set
    h, p, s = body.split(".")
    flipped = s[0] == "A" ? "B#{s[1..]}" : "A#{s[1..]}"
    expect do
      verifier.verify_set("#{h}.#{p}.#{flipped}")
    end.to raise_error(RootHerald::WebhookSignatureError)
  end
end
