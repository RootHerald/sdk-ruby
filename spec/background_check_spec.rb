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

  # ── ABI 2.0 renamed primaries (create_challenge/attest are deprecated aliases) ──

  it "issue_challenge mints a challenge with the bearer secret key" do
    seen = {}
    c = bg(lambda { |method, url, headers, _body|
      seen[:method] = method
      seen[:url] = url
      seen[:auth] = headers["Authorization"]
      { status: 200, body: JSON.generate(
        "challengeId" => "ch_2", "nonce" => "n_2", "expiresAt" => "2030-01-01T00:00:00Z"
      ) }
    })
    challenge = c.issue_challenge(device_hint: "dh")
    expect(challenge.challenge_id).to eq("ch_2")
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/attestations/challenge")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
  end

  it "verify submits opaque evidence and maps a pass verdict" do
    seen = {}
    c = bg(lambda { |_method, url, _headers, body|
      seen[:url] = url
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate("verdict" => { "verdict" => "pass" }, "token" => "eyJ.x.y") }
    })
    result = c.verify({ "quote" => "..." }, challenge_id: "ch_1", policy: "default", return_token: true)
    expect(result.verdict).to eq(:allow)
    expect(result.token).to eq("eyJ.x.y")
    expect(seen[:url]).to end_with("/api/v1/attestations/verify")
    expect(seen[:body]["challengeId"]).to eq("ch_1")
    expect(seen[:body]["evidence"]["quote"]).to eq("...")
    expect(seen[:body]["policy"]).to eq("default")
    expect(seen[:body]["returnToken"]).to eq(true)
  end

  it "verify requires a challenge_id" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.verify({}, challenge_id: "") }.to raise_error(RootHerald::ChallengeError)
  end

  it "keeps create_challenge / attest as working deprecated aliases" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "verdict" => "pass" }) } })
    expect(c.attest({}, challenge_id: "ch_1").verdict).to eq(:allow)
    c2 = bg(->(*_args) {
      { status: 200, body: JSON.generate("challengeId" => "c", "nonce" => "n", "expiresAt" => "2030-01-01T00:00:00Z") }
    })
    expect(c2.create_challenge.challenge_id).to eq("c")
  end

  # ── relay_enroll (POST /api/v1/devices/enroll) ──

  it "relay_enroll on 201 returns the MakeCredential challenge (fresh enroll)" do
    seen = {}
    c = bg(lambda { |method, url, headers, body|
      seen[:method] = method
      seen[:url] = url
      seen[:auth] = headers["Authorization"]
      seen[:body] = JSON.parse(body)
      { status: 201, body: JSON.generate(
        "deviceId" => "dev-1", "credentialBlob" => "cred==", "encryptedSecret" => "sec=="
      ) }
    })
    blob = {
      "ekPublicKey" => "ekpub==", "akPublicArea" => "akpub==", "platform" => "windows",
      "ekCertPem" => "-----BEGIN CERTIFICATE-----", "ekCertificateChain" => ["int=="]
    }
    result = c.relay_enroll(blob)
    expect(result.already_enrolled?).to be(false)
    expect(result.device_id).to eq("dev-1")
    expect(result.challenge.credential_blob).to eq("cred==")
    expect(result.challenge.encrypted_secret).to eq("sec==")
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/devices/enroll")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
    # opaque pass-through: every wire field relayed verbatim
    expect(seen[:body]).to eq(blob)
  end

  it "relay_enroll on 409 returns already_enrolled and skips activate" do
    c = bg(->(*_args) { { status: 409, body: JSON.generate("deviceId" => "dev-9") } })
    result = c.relay_enroll("ekPublicKey" => "e", "akPublicArea" => "a")
    expect(result.already_enrolled?).to be(true)
    expect(result.device_id).to eq("dev-9")
    expect(result.challenge).to be_nil
  end

  it "relay_enroll raises if a 409 omits deviceId" do
    c = bg(->(*_args) { { status: 409, body: "{}" } })
    expect { c.relay_enroll("ekPublicKey" => "e", "akPublicArea" => "a") }
      .to raise_error(RootHerald::HttpError, /missing deviceId/)
  end

  it "relay_enroll validates required blob fields before any network call" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.relay_enroll("ekPublicKey" => "e") }.to raise_error(ArgumentError)
    expect { c.relay_enroll({}) }.to raise_error(ArgumentError)
  end

  it "relay_enroll accepts symbol-keyed blobs" do
    c = bg(->(*_args) {
      { status: 201, body: JSON.generate("deviceId" => "d", "credentialBlob" => "c", "encryptedSecret" => "s") }
    })
    result = c.relay_enroll(ekPublicKey: "e", akPublicArea: "a")
    expect(result.device_id).to eq("d")
  end

  it "relay_enroll maps a 401 to InvalidSecretKeyError" do
    c = bg(->(*_args) { { status: 401, body: '{"message":"nope"}' } })
    expect { c.relay_enroll("ekPublicKey" => "e", "akPublicArea" => "a") }
      .to raise_error(RootHerald::InvalidSecretKeyError)
  end

  # ── relay_activate (POST /api/v1/devices/activate) ──

  it "relay_activate relays the decrypted secret and returns the device" do
    seen = {}
    c = bg(lambda { |_method, url, _headers, body|
      seen[:url] = url
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate(
        "deviceId" => "dev-1", "status" => "enrolled", "enrolledAt" => "2030-01-01T00:00:00Z"
      ) }
    })
    result = c.relay_activate("deviceId" => "dev-1", "decryptedSecret" => "secret==")
    expect(result.device_id).to eq("dev-1")
    expect(result.status).to eq("enrolled")
    expect(result.enrolled_at).to eq("2030-01-01T00:00:00Z")
    expect(seen[:url]).to end_with("/api/v1/devices/activate")
    expect(seen[:body]).to eq("deviceId" => "dev-1", "decryptedSecret" => "secret==")
  end

  it "relay_activate validates required blob fields" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.relay_activate("deviceId" => "d") }.to raise_error(ArgumentError)
    expect { c.relay_activate("decryptedSecret" => "s") }.to raise_error(ArgumentError)
  end

  it "relay_activate maps a 409 to ChallengeError" do
    c = bg(->(*_args) { { status: 409, body: '{"message":"stale"}' } })
    expect { c.relay_activate("deviceId" => "d", "decryptedSecret" => "s") }
      .to raise_error(RootHerald::ChallengeError)
  end
end
