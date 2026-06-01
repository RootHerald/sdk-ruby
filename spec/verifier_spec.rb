# frozen_string_literal: true

require "spec_helper"

RSpec.describe RootHerald::Verifier do
  def verifier(audience: Fixtures::AUDIENCE)
    RootHerald::Verifier.new(
      issuer: Fixtures::ISSUER,
      jwks: Fixtures.jwks_fetcher,
      audience: audience
    )
  end

  it "decodes a happy-path token to ALLOW" do
    claims = verifier.verify(Fixtures.make_token)
    expect(claims.verdict).to eq(:allow)
    expect(claims.device_id).to eq("device-uuid-1234")
    expect(claims.acr).to eq("urn:rootherald:user:phr")
  end

  it "maps warning ear_status to WARN" do
    claims = verifier.verify(Fixtures.make_token(ear_status: "warning"))
    expect(claims.verdict).to eq(:warn)
    expect(claims.warn?).to be(true)
  end

  it "maps contraindicated ear_status to DENY" do
    claims = verifier.verify(Fixtures.make_token(ear_status: "contraindicated"))
    expect(claims.verdict).to eq(:deny)
    expect(claims.deny?).to be(true)
  end

  it "rejects expired tokens with TokenExpiredError" do
    token = Fixtures.make_token(iat: Time.now.to_i - 3600, exp_in: -600)
    expect { verifier.verify(token) }.to raise_error(RootHerald::TokenExpiredError)
  end

  it "rejects wrong issuer" do
    expect do
      verifier.verify(Fixtures.make_token(issuer: "https://evil.example/myorg"))
    end.to raise_error(RootHerald::VerificationError)
  end

  it "rejects wrong audience" do
    expect do
      verifier.verify(Fixtures.make_token(audience: "not-our-aud"))
    end.to raise_error(RootHerald::VerificationError)
  end

  it "rejects missing ueid" do
    expect do
      verifier.verify(Fixtures.make_token(device_overrides: { "ueid" => "" }))
    end.to raise_error(RootHerald::VerificationError)
  end

  it "rejects wrong eat_profile" do
    expect do
      verifier.verify(Fixtures.make_token(eat_profile: "tag:bogus:v0"))
    end.to raise_error(RootHerald::VerificationError)
  end

  it "rejects unknown kid" do
    expect do
      verifier.verify(Fixtures.make_token(kid: "some-other-kid"))
    end.to raise_error(RootHerald::VerificationError)
  end

  it "rejects alg=none forgeries" do
    header = JWT::Base64.url_encode(JSON.generate("alg" => "none", "kid" => Fixtures::KID, "typ" => "JWT"))
    body = JWT::Base64.url_encode(JSON.generate("iss" => Fixtures::ISSUER, "sub" => "u",
                                                "exp" => Time.now.to_i + 60))
    expect { verifier.verify("#{header}.#{body}.") }.to raise_error(RootHerald::VerificationError)
  end

  it "rejects tampered signature" do
    token = Fixtures.make_token
    h, b, s = token.split(".")
    flipped = b[0] == "X" ? "Y#{b[1..]}" : "X#{b[1..]}"
    expect do
      verifier.verify("#{h}.#{flipped}.#{s}")
    end.to raise_error(RootHerald::VerificationError)
  end

  it "skips audience check when nil" do
    claims = verifier(audience: nil).verify(Fixtures.make_token(audience: "anything"))
    expect(claims.device_id).to eq("device-uuid-1234")
  end

  it "preserves the raw payload on the claims object" do
    claims = verifier.verify(Fixtures.make_token)
    expect(claims.raw["iss"]).to eq(Fixtures::ISSUER)
    expect(claims.raw).to have_key("rootherald_device")
  end
end
