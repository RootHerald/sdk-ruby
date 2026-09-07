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
    expect(challenge.challenge).to be_nil
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/attest/challenge")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
  end

  # ── the challenge carries the ask ──

  it "issue_challenge sends the ask, policy and key purpose and returns the challenge string" do
    seen = {}
    c = bg(lambda { |_method, _url, _headers, body|
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate(
        "challengeId" => "ch_1", "challenge" => "rhc1.bm9uY2U.eyJhc2siOlsia2V5Il19",
        "nonce" => "n_1", "expiresAt" => "2030-01-01T00:00:00Z"
      ) }
    })
    challenge = c.issue_challenge(
      device_hint: "hint",
      ask: [RootHerald::Client::ASK_IDENTITY, :key],
      policy: "rootherald:builtin:strict-hardware",
      key_purpose: RootHerald::Client::KEY_PURPOSE_SIGN
    )
    expect(challenge.challenge).to eq("rhc1.bm9uY2U.eyJhc2siOlsia2V5Il19")
    expect(challenge.nonce).to eq("n_1")
    expect(seen[:body]["ask"]).to eq(%w[identity key])
    expect(seen[:body]["policy"]).to eq("rootherald:builtin:strict-hardware")
    expect(seen[:body]["keyPurpose"]).to eq("sign")
    expect(seen[:body]["deviceHint"]).to eq("hint")
  end

  it "issue_challenge omits every unset field, an empty ask included" do
    seen = {}
    c = bg(lambda { |_method, _url, _headers, body|
      seen[:body] = JSON.parse(body)
      { status: 200, body: JSON.generate(
        "challengeId" => "ch_1", "nonce" => "n_1", "expiresAt" => "2030-01-01T00:00:00Z"
      ) }
    })
    c.issue_challenge
    expect(seen[:body]).to eq({})
    c.issue_challenge(ask: [])
    expect(seen[:body]).to eq({})
  end

  let(:passing_verdict_with_key) do
    {
      "verdict" => { "device" => { "verdict" => "pass", "ueid" => "dev-9" } },
      "assuranceClaimsMet" => [],
      "enrollmentRequired" => false,
      "key" => {
        "keyId" => "key_1",
        "jwk" => { "kty" => "EC", "crv" => "P-256", "x" => "eHg", "y" => "eXk" },
        "purpose" => "sign",
        "authPolicy" => "cG9saWN5",
        "certifiedAt" => "2030-01-01T00:01:00Z"
      }
    }
  end

  it "verify exposes the certified key from the response root" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate(passing_verdict_with_key) } })
    result = c.verify({}, challenge_id: "ch_1")
    expect(result.verdict).to eq(:allow)
    key = result.key
    expect(key).to be_a(RootHerald::Client::CertifiedKey)
    expect(key.key_id).to eq("key_1")
    expect(key.jwk).to eq("kty" => "EC", "crv" => "P-256", "x" => "eHg", "y" => "eXk")
    expect(key.purpose).to eq("sign")
    expect(key.auth_policy).to eq("cG9saWN5")
    expect(key.certified_at).to eq(Time.utc(2030, 1, 1, 0, 1, 0))
  end

  it "verify leaves key nil when the server omits it" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" } }) } })
    expect(c.verify({}, challenge_id: "ch_1").key).to be_nil
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" } }, "key" => nil) }
    })
    expect(c.verify({}, challenge_id: "ch_1").key).to be_nil
  end

  it "verify treats authPolicy as optional on the key" do
    wire = passing_verdict_with_key
    wire["key"].delete("authPolicy")
    c = bg(->(*_args) { { status: 200, body: JSON.generate(wire) } })
    expect(c.verify({}, challenge_id: "ch_1").key.auth_policy).to be_nil
  end

  it "verify rejects a malformed key" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" } }, "key" => { "keyId" => "k" }) }
    })
    expect { c.verify({}, challenge_id: "ch_1") }.to raise_error(RootHerald::HttpError, /key/)
  end

  it "maps a 422 policy_downgrade to PolicyDowngradeError with the server code" do
    c = bg(->(*_args) {
      { status: 422, body: '{"error":"policy_downgrade","message":"verify policy is looser than the challenge"}' }
    })
    expect { c.verify({}, challenge_id: "ch_1", policy: "loose") }.to raise_error(RootHerald::PolicyDowngradeError) { |e|
      expect(e.code).to eq("policy_downgrade")
      expect(e.server_error).to eq("policy_downgrade")
      expect(e.status).to eq(422)
      expect(e.message).to eq("verify policy is looser than the challenge")
    }
  end

  it "carries the server error code on every typed error" do
    c = bg(->(*_args) { { status: 422, body: '{"error":"unknown_policy"}' } })
    expect { c.verify({}, challenge_id: "ch_1") }.to raise_error(RootHerald::UnknownPolicyError) { |e|
      expect(e.server_error).to eq("unknown_policy")
    }
    c = bg(->(*_args) { { status: 409, body: '{"error":"challenge_expired_or_used","detail":"used"}' } })
    expect { c.verify({}, challenge_id: "ch_1") }.to raise_error(RootHerald::ChallengeError) { |e|
      expect(e.server_error).to eq("challenge_expired_or_used")
      expect(e.message).to eq("used")
    }
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
    expect(seen[:url]).to end_with("/api/v1/attest/challenge")
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
    expect(seen[:url]).to end_with("/api/v1/attest/verify")
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

  
  # ── relay_enroll (POST /api/v1/attest/enroll) ──

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
    expect(result.device_id).to eq("dev-1")
    expect(result.challenge.credential_blob).to eq("cred==")
    expect(result.challenge.encrypted_secret).to eq("sec==")
    expect(result.challenge_id).to be_nil
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/attest/enroll")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
    # opaque pass-through: every wire field relayed verbatim
    expect(seen[:body]).to eq(blob)
  end

  it "relay_enroll with a challenge_id sends the query parameter and echoes it back" do
    seen = {}
    c = bg(lambda { |_method, url, _headers, body|
      seen[:url] = url
      seen[:body] = JSON.parse(body)
      { status: 201, body: JSON.generate(
        "deviceId" => "dev-1", "credentialBlob" => "cred==", "encryptedSecret" => "sec==", "challengeId" => "ch 1"
      ) }
    })
    result = c.relay_enroll({ "ekPublicKey" => "e", "akPublicArea" => "a" }, challenge_id: "ch 1")
    expect(seen[:url]).to end_with("/api/v1/attest/enroll?challengeId=ch+1")
    expect(seen[:body]).not_to have_key("challengeId")
    expect(result.challenge_id).to eq("ch 1")
    expect(result.device_id).to eq("dev-1")
  end

  it "relay_enroll maps a 422 admission_refused to AdmissionRefusedError" do
    c = bg(->(*_args) {
      { status: 422, body: '{"error":"admission_refused","detail":"firmware TPM under a discrete-only policy"}' }
    })
    expect { c.relay_enroll({ "ekPublicKey" => "e", "akPublicArea" => "a" }, challenge_id: "ch_1") }
      .to raise_error(RootHerald::AdmissionRefusedError) { |e|
        expect(e.code).to eq("admission_refused")
        expect(e.server_error).to eq("admission_refused")
        expect(e.message).to eq("firmware TPM under a discrete-only policy")
      }
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

  # ── relay_activate (POST /api/v1/attest/activate) ──

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
    expect(seen[:url]).to end_with("/api/v1/attest/activate")
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
