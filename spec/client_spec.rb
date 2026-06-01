# frozen_string_literal: true

require "spec_helper"

RSpec.describe RootHerald::Client do
  def client(http_transport)
    RootHerald::Client.new(
      issuer: Fixtures::ISSUER,
      api_key: "rh_sk_test_xxx",
      base_url: "https://rootherald.io",
      audience: Fixtures::AUDIENCE,
      jwks_fetcher: Fixtures.jwks_fetcher,
      http_transport: http_transport
    )
  end

  it "GETs a device and returns parsed JSON" do
    seen = {}
    c = client(lambda { |method, url, headers, _body|
      seen[:method] = method
      seen[:url] = url
      seen[:auth] = headers["Authorization"]
      { status: 200, body: JSON.generate("id" => "dev-123", "tpm_class" => "hardware") }
    })
    out = c.get_device("dev-123")
    expect(out["id"]).to eq("dev-123")
    expect(seen[:method]).to eq(:get)
    expect(seen[:url]).to end_with("/api/v1/devices/dev-123")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
  end

  it "POSTs an attestation evidence body" do
    seen = {}
    c = client(lambda { |method, _url, _headers, body|
      seen[:method] = method
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate("verdict" => "pass") }
    })
    out = c.verify_attestation({ "pcr_blob" => "..." }, action: "signup")
    expect(out["verdict"]).to eq("pass")
    expect(seen[:method]).to eq(:post)
    expect(seen[:body]["action"]).to eq("signup")
  end

  it "raises HttpError on non-2xx responses" do
    c = client(->(*_args) { { status: 403, body: '{"error":"forbidden"}' } })
    expect { c.get_device("d-403") }.to raise_error(RootHerald::HttpError) do |e|
      expect(e.status).to eq(403)
    end
  end

  it "verify_token facade uses the shared JWKS" do
    c = client(->(*_args) { { status: 404, body: "" } })
    claims = c.verify_token(Fixtures.make_token)
    expect(claims.device_id).to eq("device-uuid-1234")
  end

  it "verify_set facade decodes SETs" do
    c = client(->(*_args) { { status: 404, body: "" } })
    event = c.verify_set(Fixtures.make_set)
    expect(event.device_id).to eq("device-uuid-1234")
  end
end
