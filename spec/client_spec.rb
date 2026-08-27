# frozen_string_literal: true

require "spec_helper"

RSpec.describe RootHerald::Client do
  def bg(http_transport)
    RootHerald::Client.new(
      secret_key: "rh_sk_test_xxx",
      base_url: "https://api.example.test",
      http_transport: http_transport
    )
  end

  it "rejects a key without the rh_sk_ prefix" do
    expect { RootHerald::Client.new(secret_key: "rh_bogus_abc") }
      .to raise_error(ArgumentError)
  end

  # The secret rides in an Authorization header on every request and is
  # full-privilege, so a base URL that is not https hands it to anyone on the
  # path. A typo is enough, and nothing downstream notices because the request
  # still succeeds.
  [
    "http://api.example.test",
    "http://rootherald.io",
    "api.example.test",
    "//api.example.test",
    ""
  ].each do |bad|
    it "rejects the insecure base_url #{bad.inspect}" do
      expect { RootHerald::Client.new(secret_key: "rh_sk_test_xxx", base_url: bad) }
        .to raise_error(ArgumentError, /https/)
    end
  end

  # Loopback stays usable so the local docker stack works over http.
  [
    "https://api.example.test",
    "http://localhost:8080",
    "http://127.0.0.1:5000",
    "http://[::1]:5000"
  ].each do |good|
    it "accepts the base_url #{good.inspect}" do
      expect { RootHerald::Client.new(secret_key: "rh_sk_test_xxx", base_url: good) }
        .not_to raise_error
    end
  end

  it "rejects an empty key" do
    expect { RootHerald::Client.new(secret_key: "") }
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
    challenge = c.issue_challenge(device_hint: "device-hint")
    expect(challenge.challenge_id).to eq("ch_1")
    expect(challenge.nonce).to eq("n_1")
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/attestations/challenge")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
  end

  it "attests and maps a pass verdict, surfacing the parity fields" do
    seen = {}
    c = bg(lambda { |_method, _url, _headers, body|
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate(
        "verdict" => { "device" => { "verdict" => "pass", "ueid" => "dev-9", "earStatus" => "affirming" } },
        "assuranceClaimsMet" => ["urn:rootherald:assurance:hardware-backed"],
        "enrollmentRequired" => false
      ) }
    })
    result = c.verify({ "quote" => "..." }, challenge_id: "ch_1")
    expect(result.verdict).to eq(:allow)
    expect(result.assurance_claims_met).to eq(["urn:rootherald:assurance:hardware-backed"])
    expect(result.enrollment_required).to be(false)
    expect(seen[:body]["challengeId"]).to eq("ch_1")
    expect(seen[:body]["evidence"]["quote"]).to eq("...")
  end

  it "exposes cohort fields from verdict.device" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate(
        "verdict" => {
          "device" => {
            "verdict" => "pass",
            "ueid" => "dev-9",
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
    result = c.verify({}, challenge_id: "ch_1")
    expect(result.cohort_key).to eq("tpm20:win11:sb1:abc123")
    expect(result.cohort_scope).to eq("tenant-fleet")
    expect(result.cohort_prevalence).to eq(0.042)
    expect(result.cohort_prevalence_per_pcr["7"]).to eq(0.5)
    expect(result.cohort_sample_size).to eq(1287)
    expect(result.novel_profile).to eq(false)
  end

  it "leaves cohort accessors nil when the server omits them" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" } }) } })
    result = c.verify({}, challenge_id: "ch_1")
    expect(result.cohort_key).to be_nil
    expect(result.cohort_prevalence).to be_nil
    expect(result.novel_profile).to be_nil
    expect(result.cohort_prevalence_per_pcr).to eq({})
  end

  it "treats a fail verdict as a verdict, not an error" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "fail" } }) } })
    result = c.verify({}, challenge_id: "ch_1")
    expect(result.verdict).to eq(:deny)
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
      expect { c.verify({}, challenge_id: "ch_1") }.to raise_error(klass)
    end
  end

  # ── the primaries ──

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
      { status: 200, body: JSON.generate(
        "verdict" => { "device" => { "verdict" => "pass" } },
        "assuranceClaimsMet" => [],
        "enrollmentRequired" => false
      ) }
    })
    result = c.verify({ "quote" => "..." }, challenge_id: "ch_1", policy: "default")
    expect(result.verdict).to eq(:allow)
    expect(seen[:url]).to end_with("/api/v1/attestations/verify")
    expect(seen[:body]["challengeId"]).to eq("ch_1")
    expect(seen[:body]["evidence"]["quote"]).to eq("...")
    expect(seen[:body]["policy"]).to eq("default")
    # requestedDisclosureClass is omitted when not supplied
    expect(seen[:body]).not_to have_key("requestedDisclosureClass")
  end

  it "verify sends requestedDisclosureClass when supplied" do
    seen = {}
    c = bg(lambda { |_method, _url, _headers, body|
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" } }) }
    })
    c.verify({}, challenge_id: "ch_1", requested_disclosure_class: "pseudonymous")
    expect(seen[:body]["requestedDisclosureClass"]).to eq("pseudonymous")
  end

  it "verify signals enrollment_required on an enroll-on-miss response" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate(
        "verdict" => { "device" => { "verdict" => "fail" } },
        "assuranceClaimsMet" => [],
        "enrollmentRequired" => true
      ) }
    })
    result = c.verify({}, challenge_id: "ch_1")
    expect(result.verdict).to eq(:deny)
    expect(result.enrollment_required).to be(true)
  end

  it "verify requires a challenge_id" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.verify({}, challenge_id: "") }.to raise_error(RootHerald::ChallengeError)
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
