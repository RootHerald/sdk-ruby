# frozen_string_literal: true

require "spec_helper"

RSpec.describe RootHerald::BackgroundCheck do
  def bg(http_transport)
    RootHerald::BackgroundCheck.new(
      secret_key: "rh_sk_test_xxx",
      base_url: "https://api.example.test",
      http_transport: http_transport
    )
  end

  it "rejects a publishable key" do
    expect { RootHerald::BackgroundCheck.new(secret_key: "rh_pk_live_abc") }
      .to raise_error(ArgumentError)
  end

  it "rejects an empty key" do
    expect { RootHerald::BackgroundCheck.new(secret_key: "") }
      .to raise_error(ArgumentError)
  end

  it "mints a challenge with the bearer secret key" do
    seen = {}
    c = bg(lambda { |method, url, headers, _body|
      seen[:method] = method
      seen[:url] = url
      seen[:auth] = headers["Authorization"]
      { status: 200, body: JSON.generate(
        "challengeId" => "ch_1", "nonce" => "n_1", "expiresAt" => "2030-01-01T00:00:00Z"
      ) }
    })
    challenge = c.create_challenge(device_hint: "device-hint")
    expect(challenge.challenge_id).to eq("ch_1")
    expect(challenge.nonce).to eq("n_1")
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/attestations/challenge")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
  end

  it "attests and maps a pass verdict, surfacing the token" do
    seen = {}
    c = bg(lambda { |_method, _url, _headers, body|
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate(
        "verdict" => { "verdict" => "pass", "ueid" => "dev-9" },
        "token" => "eyJ.signed.eat"
      ) }
    })
    result = c.attest({ "quote" => "..." }, challenge_id: "ch_1", return_token: true)
    expect(result.verdict).to eq(:allow)
    expect(result.token).to eq("eyJ.signed.eat")
    expect(seen[:body]["challengeId"]).to eq("ch_1")
    expect(seen[:body]["evidence"]["quote"]).to eq("...")
  end

  it "exposes cohort fields from verdict.device" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate(
        "verdict" => {
          "verdict" => "pass",
          "ueid" => "dev-9",
          "device" => {
            "cohortKey" => "tpm20:win11:sb1:abc123",
            "cohortScope" => "tenant-fleet",
            "cohortPrevalence" => 0.042,
            "cohortPrevalencePerPcr" => { "0" => 0.9, "7" => 0.5 },
            "cohortSampleSize" => 1287,
            "novelProfile" => false
          }
        }
      ) }
    })
    result = c.attest({}, challenge_id: "ch_1")
    expect(result.cohort_key).to eq("tpm20:win11:sb1:abc123")
    expect(result.cohort_scope).to eq("tenant-fleet")
    expect(result.cohort_prevalence).to eq(0.042)
    expect(result.cohort_prevalence_per_pcr["7"]).to eq(0.5)
    expect(result.cohort_sample_size).to eq(1287)
    expect(result.novel_profile).to eq(false)
  end

  it "leaves cohort accessors nil when the server omits them" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "verdict" => "pass" }) } })
    result = c.attest({}, challenge_id: "ch_1")
    expect(result.cohort_key).to be_nil
    expect(result.cohort_prevalence).to be_nil
    expect(result.novel_profile).to be_nil
    expect(result.cohort_prevalence_per_pcr).to eq({})
  end

  it "treats a fail verdict as a verdict, not an error" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "verdict" => "fail" }) } })
    result = c.attest({}, challenge_id: "ch_1")
    expect(result.verdict).to eq(:deny)
    expect(result.token).to be_nil
  end

  {
    401 => RootHerald::InvalidSecretKeyError,
    422 => RootHerald::UnknownPolicyError,
    409 => RootHerald::ChallengeError,
    400 => RootHerald::InvalidEvidenceError,
    429 => RootHerald::QuotaExceededError
  }.each do |status, klass|
    it "maps HTTP #{status} to #{klass}" do
      c = bg(->(*_args) { { status: status, body: '{"error":"x","message":"boom"}' } })
      expect { c.attest({}, challenge_id: "ch_1") }.to raise_error(klass)
    end
  end
end
