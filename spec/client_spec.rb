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

  # A transport that records the request and answers +status+ / +wire+.
  def recording(seen, status, wire)
    lambda do |method, url, headers, body|
      seen[:method] = method
      seen[:url] = url
      seen[:auth] = headers["Authorization"]
      seen[:body] = JSON.parse(body)
      { status: status, body: wire.is_a?(String) ? wire : JSON.generate(wire) }
    end
  end

  let(:challenge_wire) do
    {
      "nonce" => "bm9uY2U", "challenge" => "rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0",
      "expiresAt" => "2030-01-01T00:00:00Z"
    }
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

  # ── issue_challenge (POST /api/v1/attest/challenge) ──

  it "issue_challenge mints a challenge with the bearer secret key" do
    seen = {}
    c = bg(recording(seen, 200, challenge_wire))
    challenge = c.issue_challenge
    expect(challenge.nonce).to eq("bm9uY2U")
    expect(challenge.challenge).to eq("rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0")
    expect(challenge.expires_at).to eq("2030-01-01T00:00:00Z")
    expect(challenge).not_to respond_to(:challenge_id)
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/attest/challenge")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
    expect(seen[:body]).to eq({})
  end

  it "issue_challenge sends the ask and the expected binding, never a policy" do
    seen = {}
    c = bg(recording(seen, 200, challenge_wire))
    c.issue_challenge(
      ask: [RootHerald::Client::ASK_IDENTITY, :posture],
      expected_key: "key_1",
      expected_devices: %w[dev-9 dev-10]
    )
    expect(seen[:body]).to eq(
      "ask" => %w[identity posture], "expectedKey" => "key_1", "expectedDevices" => %w[dev-9 dev-10]
    )
    expect(seen[:body]).not_to have_key("policy")
  end

  it "issue_challenge has no device_hint, key_purpose or policy keyword" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.issue_challenge(device_hint: "hint") }.to raise_error(ArgumentError)
    expect { c.issue_challenge(key_purpose: "sign") }.to raise_error(ArgumentError)
    expect { c.issue_challenge(policy: "rootherald:builtin:strict-hardware") }.to raise_error(ArgumentError)
    expect { c.verify({}, nonce: "n_1", policy: "rootherald:builtin:strict-hardware") }
      .to raise_error(ArgumentError)
  end

  it "issue_challenge no longer exposes the key ask or purpose constants" do
    expect(RootHerald::Client.const_defined?(:ASK_KEY)).to be(false)
    expect(RootHerald::Client::KEY_PURPOSES).to eq(%w[sign decrypt])
  end

  it "issue_challenge refuses an empty expected binding locally" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.issue_challenge(expected_key: "") }.to raise_error(ArgumentError, /expected_key/)
    expect { c.issue_challenge(expected_devices: []) }.to raise_error(ArgumentError, /expected_devices/)
    expect { c.issue_challenge(expected_devices: ["dev-9", ""]) }.to raise_error(ArgumentError, /expected_devices/)
    expect { c.issue_challenge(expected_devices: "dev-9") }.to raise_error(ArgumentError, /expected_devices/)
  end

  it "issue_challenge omits every unset field, an empty ask included" do
    seen = {}
    c = bg(recording(seen, 200, challenge_wire))
    c.issue_challenge
    expect(seen[:body]).to eq({})
    c.issue_challenge(ask: [])
    expect(seen[:body]).to eq({})
  end

  it "issue_challenge rejects a response without the challenge string or nonce" do
    %w[nonce challenge expiresAt].each do |missing|
      wire = challenge_wire.reject { |k, _| k == missing }
      c = bg(->(*_args) { { status: 200, body: JSON.generate(wire) } })
      expect { c.issue_challenge }.to raise_error(RootHerald::HttpError, /#{missing}/)
    end
  end

  # The retired "key" ask is a programming error in the backend, not a device
  # failure, so it must not land in the class an un-parseable blob lands in.
  it "maps a 400 invalid_ask to InvalidAskError, not InvalidEvidenceError" do
    c = bg(->(*_args) { { status: 400, body: '{"error":"invalid_ask","message":"ask \"key\" is not known"}' } })
    expect { c.issue_challenge(ask: %w[identity key]) }.to raise_error(RootHerald::InvalidAskError) { |e|
      expect(e).not_to be_a(RootHerald::InvalidEvidenceError)
      expect(e.code).to eq("invalid_ask")
      expect(e.server_error).to eq("invalid_ask")
      expect(e.status).to eq(400)
    }
  end

  # ── verify (POST /api/v1/attest/verify) ──

  it "verify submits opaque evidence with the nonce and maps a pass verdict" do
    seen = {}
    c = bg(recording(seen, 200,
                     "verdict" => { "device" => { "verdict" => "pass", "ueid" => "dev-9", "earStatus" => "affirming" } },
                     "assuranceClaimsMet" => ["urn:rootherald:assurance:hardware-backed"],
                     "enrollmentRequired" => false))
    result = c.verify({ "quote" => "..." }, nonce: "n_1")
    expect(result.verdict).to eq(:pass)
    expect(result.device_id).to eq("dev-9")
    expect(result.assurance_claims_met).to eq(["urn:rootherald:assurance:hardware-backed"])
    expect(result.enrollment_required).to be(false)
    expect(result.expected).to eq({})
    expect(result).not_to respond_to(:key)
    expect(seen[:url]).to end_with("/api/v1/attest/verify")
    expect(seen[:body]["nonce"]).to eq("n_1")
    expect(seen[:body]["evidence"]["quote"]).to eq("...")
    expect(seen[:body]).not_to have_key("challengeId")
    # the policy is pinned on the challenge at mint; the body never names one
    expect(seen[:body]).not_to have_key("policy")
    # requestedDisclosureClass is omitted when not supplied
    expect(seen[:body]).not_to have_key("requestedDisclosureClass")
  end

  it "verify sends requestedDisclosureClass when supplied" do
    seen = {}
    c = bg(recording(seen, 200, "verdict" => { "device" => { "verdict" => "pass" } }))
    c.verify({}, nonce: "n_1", requested_disclosure_class: "pseudonymous")
    expect(seen[:body]["requestedDisclosureClass"]).to eq("pseudonymous")
  end

  it "verify sends the expected binding nowhere: it was bound at mint" do
    seen = {}
    c = bg(recording(seen, 200,
                     "verdict" => { "device" => { "verdict" => "pass", "ueid" => "dev-9" },
                                    "expected" => { "key" => "key_1", "devices" => ["dev-9"] } }))
    result = c.verify({}, nonce: "n_1", expected_key: "key_1", expected_devices: ["dev-9"])
    expect(seen[:body].keys).to contain_exactly("nonce", "evidence")
    expect(result.expected).to eq("key" => "key_1", "devices" => ["dev-9"])
  end

  # The API ignores unknown JSON fields, so a server that predates the binding
  # would accept any device and answer with no `expected` block.
  it "verify refuses a verdict that does not echo the expected binding" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass", "ueid" => "dev-9" } }) } })
    expect { c.verify({}, nonce: "n_1", expected_devices: ["dev-9"]) }
      .to raise_error(RootHerald::ExpectedNotEnforcedError, /expected_devices/) { |e|
        expect(e.code).to eq("expected_not_enforced")
        expect(e.status).to eq(200)
      }
    expect { c.verify({}, nonce: "n_1", expected_key: "key_1") }
      .to raise_error(RootHerald::ExpectedNotEnforcedError, /expected_key/)

    other_key = bg(->(*_args) {
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" },
                                                        "expected" => { "key" => "key_2" } }) }
    })
    expect { other_key.verify({}, nonce: "n_1", expected_key: "key_1") }
      .to raise_error(RootHerald::ExpectedNotEnforcedError)

    other_set = bg(->(*_args) {
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass", "ueid" => "dev-9" },
                                                        "expected" => { "devices" => %w[dev-9 dev-10] } }) }
    })
    expect { other_set.verify({}, nonce: "n_1", expected_devices: ["dev-9"]) }
      .to raise_error(RootHerald::ExpectedNotEnforcedError)
  end

  it "verify refuses a passing verdict naming a device outside expected_devices" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass", "ueid" => "dev-7" },
                                                        "expected" => { "devices" => ["dev-9"] } }) }
    })
    expect { c.verify({}, nonce: "n_1", expected_devices: ["dev-9"]) }
      .to raise_error(RootHerald::ExpectedNotEnforcedError)
  end

  # On a mismatch the server fails the verdict and reports the device that
  # actually answered; that is the enforced outcome, not a missing one.
  it "verify accepts a failing verdict naming the mismatched device" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "fail", "ueid" => "dev-7",
                                                                      "reason" => "expected_device_mismatch" },
                                                        "expected" => { "devices" => ["dev-9"] } }) }
    })
    result = c.verify({}, nonce: "n_1", expected_devices: ["dev-9"])
    expect(result.verdict).to eq(:fail)
    expect(result.device_id).to eq("dev-7")
  end

  it "verify does not compare the echo when nothing was expected" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" },
                                                        "expected" => { "key" => "key_1" } }) }
    })
    expect(c.verify({}, nonce: "n_1").expected).to eq("key" => "key_1")
  end

  it "verify refuses an empty expected binding locally" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.verify({}, nonce: "n_1", expected_key: "") }.to raise_error(ArgumentError, /expected_key/)
    expect { c.verify({}, nonce: "n_1", expected_devices: []) }.to raise_error(ArgumentError, /expected_devices/)
  end

  it "verify ignores a key beside the verdict: attestation releases no key" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate(
        "verdict" => { "device" => { "verdict" => "pass" } },
        "key" => { "keyId" => "key_1", "jwk" => { "kty" => "EC", "crv" => "P-256", "x" => "eHg", "y" => "eXk" } }
      ) }
    })
    result = c.verify({}, nonce: "n_1")
    expect(result.verdict).to eq(:pass)
    expect(result.to_h).not_to have_key(:key)
  end

  it "verify signals enrollment_required on an enroll-on-miss response" do
    c = bg(->(*_args) {
      { status: 200, body: JSON.generate(
        "verdict" => { "device" => { "verdict" => "fail" } },
        "assuranceClaimsMet" => [],
        "enrollmentRequired" => true
      ) }
    })
    result = c.verify({}, nonce: "n_1")
    expect(result.verdict).to eq(:fail)
    expect(result.enrollment_required).to be(true)
  end

  it "verify requires a nonce, as a local argument error" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.verify({}, nonce: "") }.to raise_error(ArgumentError, /nonce/)
    expect { c.verify({}, nonce: nil) }.to raise_error(ArgumentError, /nonce/)
    expect { c.verify({}, challenge_id: "ch_1") }.to raise_error(ArgumentError)
  end

  it "refuses a verdict token outside pass/warn/fail" do
    ["allow", "review", "", nil, 7].each do |token|
      c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => token } }) } })
      expect { c.verify({}, nonce: "n_1") }
        .to raise_error(RootHerald::HttpError, /verdict\.device\.verdict/), token.inspect
    end
  end

  it "returns warn as the server's token" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "warn" } }) } })
    expect(c.verify({}, nonce: "n_1").verdict).to eq(:warn)
  end

  it "treats a fail verdict as a verdict, not an error" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "fail" } }) } })
    result = c.verify({}, nonce: "n_1")
    expect(result.verdict).to eq(:fail)
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
    result = c.verify({}, nonce: "n_1")
    expect(result.cohort_key).to eq("tpm20:win11:sb1:abc123")
    expect(result.cohort_scope).to eq("tenant-fleet")
    expect(result.cohort_prevalence).to eq(0.042)
    expect(result.cohort_prevalence_per_pcr["7"]).to eq(0.5)
    expect(result.cohort_sample_size).to eq(1287)
    expect(result.novel_profile).to eq(false)
  end

  it "leaves cohort accessors and device_id nil when the server omits them" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate("verdict" => { "device" => { "verdict" => "pass" } }) } })
    result = c.verify({}, nonce: "n_1")
    expect(result.device_id).to be_nil
    expect(result.cohort_key).to be_nil
    expect(result.cohort_prevalence).to be_nil
    expect(result.novel_profile).to be_nil
    expect(result.cohort_prevalence_per_pcr).to eq({})
  end

  it "defaults the request timeout to 30 seconds" do
    expect(RootHerald::Client::DEFAULT_TIMEOUT_SECONDS).to eq(30.0)
    expect(bg(->(*_args) { {} }).instance_variable_get(:@timeout)).to eq(30.0)
  end

  # ── error mapping ──

  it "maps a 422 unknown_policy (a policy bound to the key no longer exists) to UnknownPolicyError" do
    c = bg(->(*_args) {
      { status: 422, body: '{"error":"unknown_policy","message":"the policy bound to this key no longer exists"}' }
    })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::UnknownPolicyError) { |e|
      expect(e.code).to eq("unknown_policy")
      expect(e.server_error).to eq("unknown_policy")
      expect(e.status).to eq(422)
      expect(e.message).to eq("the policy bound to this key no longer exists")
    }
  end

  it "maps a 400 policy_bound_to_key (a policy field in a hand-built body) to InvalidEvidenceError" do
    c = bg(->(*_args) {
      { status: 400, body: '{"error":"policy_bound_to_key","message":"policy is bound to the API key"}' }
    })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::InvalidEvidenceError) { |e|
      expect(e.server_error).to eq("policy_bound_to_key")
      expect(e.status).to eq(400)
    }
  end

  it "carries the server error code on every typed error" do
    c = bg(->(*_args) { { status: 422, body: '{"error":"unknown_policy"}' } })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::UnknownPolicyError) { |e|
      expect(e.server_error).to eq("unknown_policy")
    }
    c = bg(->(*_args) { { status: 409, body: '{"error":"challenge_expired_or_used","detail":"used"}' } })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::ChallengeError) { |e|
      expect(e.server_error).to eq("challenge_expired_or_used")
      expect(e.message).to eq("used")
    }
  end

  {
    [401, "invalid_secret_key"] => RootHerald::InvalidSecretKeyError,
    [401, "activation_refused"] => RootHerald::ActivationRefusedError,
    [422, "unknown_policy"] => RootHerald::UnknownPolicyError,
    [422, "admission_refused"] => RootHerald::AdmissionRefusedError,
    [409, "x"] => RootHerald::ChallengeError,
    [400, "x"] => RootHerald::InvalidEvidenceError,
    [400, "wire_version_unsupported"] => RootHerald::InvalidEvidenceError,
    [400, "invalid_enroll_shape"] => RootHerald::InvalidEvidenceError,
    [400, "invalid_ask"] => RootHerald::InvalidAskError,
    [400, "invalid_purpose"] => RootHerald::InvalidAskError,
    [400, "invalid_certification"] => RootHerald::InvalidEvidenceError,
    [409, "challenge_expired_or_used"] => RootHerald::ChallengeError,
    [422, "purpose_unsupported"] => RootHerald::HttpError,
    [422, "certification_rejected"] => RootHerald::HttpError,
    [429, "budget_exhausted"] => RootHerald::QuotaExceededError,
    [429, "rate_limited"] => RootHerald::RateLimitedError
  }.each do |(status, code), klass|
    it "maps HTTP #{status} #{code} to #{klass}" do
      c = bg(->(*_args) { { status: status, body: JSON.generate("error" => code, "message" => "boom") } })
      expect { c.verify({}, nonce: "n_1") }.to raise_error(klass) { |e| expect(e.server_error).to eq(code) }
    end
  end

  it "maps a 401 activation_refused to ActivationRefusedError, not InvalidSecretKeyError" do
    c = bg(->(*_args) { { status: 401, body: '{"error":"activation_refused","message":"Invalid credential activation response"}' } })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::ActivationRefusedError) { |e|
      expect(e).not_to be_a(RootHerald::InvalidSecretKeyError)
      expect(e.server_error).to eq("activation_refused")
      expect(e.message).to eq("Invalid credential activation response")
    }
    bare = bg(->(*_args) { { status: 401, body: "" } })
    expect { bare.verify({}, nonce: "n_1") }.to raise_error(RootHerald::InvalidSecretKeyError)
  end

  it "maps a limiter 429 to RateLimitedError with retry_after_seconds" do
    c = bg(->(*_args) { { status: 429, body: '{"error":"rate_limited","message":"Too many requests","retryAfterSeconds":60}',
                          headers: { "Retry-After" => "17" } } })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::RateLimitedError) { |e|
      expect(e).not_to be_a(RootHerald::QuotaExceededError)
      expect(e.retry_after_seconds).to eq(17)
      expect(e.server_error).to eq("rate_limited")
    }
    from_body = bg(->(*_args) { { status: 429, body: '{"error":"rate_limited","retryAfterSeconds":60}' } })
    expect { from_body.verify({}, nonce: "n_1") }.to raise_error(RootHerald::RateLimitedError) { |e|
      expect(e.retry_after_seconds).to eq(60)
    }
    bare = bg(->(*_args) { { status: 429, body: "" } })
    expect { bare.verify({}, nonce: "n_1") }.to raise_error(RootHerald::RateLimitedError) { |e|
      expect(e.retry_after_seconds).to be_nil
    }
  end

  it "maps a 429 budget_exhausted to QuotaExceededError naming the budget" do
    c = bg(->(*_args) {
      { status: 429, body: '{"error":"budget_exhausted","message":"budget exhausted","budget":{"id":"bgt_1","name":"Production"}}',
        headers: { "X-RootHerald-Quota" => "budget-exhausted" } }
    })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::QuotaExceededError) { |e|
      expect(e.server_error).to eq("budget_exhausted")
      expect(e.budget).to eq(RootHerald::Budget.new(id: "bgt_1", name: "Production"))
      expect(e.budget.name).to eq("Production")
    }
  end

  it "maps a 429 carrying X-RootHerald-Quota to QuotaExceededError whatever the body" do
    c = bg(->(*_args) { { status: 429, body: "{}", headers: { "X-RootHerald-Quota" => "device-limit-exceeded" } } })
    expect { c.verify({}, nonce: "n_1") }.to raise_error(RootHerald::QuotaExceededError) { |e|
      expect(e.budget).to be_nil
    }
  end

  it "maps a 400 invalid_purpose to InvalidAskError, not InvalidEvidenceError" do
    c = bg(->(*_args) { { status: 400, body: '{"error":"invalid_purpose","message":"purpose must be one of sign, decrypt"}' } })
    expect { c.issue_key_challenge(purpose: RootHerald::Client::KEY_PURPOSE_SIGN) }
      .to raise_error(RootHerald::InvalidAskError) { |e|
        expect(e).not_to be_a(RootHerald::InvalidEvidenceError)
        expect(e.server_error).to eq("invalid_purpose")
        expect(e.status).to eq(400)
      }
  end

  it "keeps a 409 key_rotation_conflict generic, with the code, not ChallengeError" do
    c = bg(->(*_args) { { status: 409, body: '{"error":"key_rotation_conflict","message":"another mint is in flight"}' } })
    expect { c.certify_key({ "publicArea" => "p", "attest" => "a", "signature" => "s" }, nonce: "n_1") }
      .to raise_error(RootHerald::HttpError) { |e|
        expect(e).not_to be_a(RootHerald::ChallengeError)
        expect(e.status).to eq(409)
        expect(e.server_error).to eq("key_rotation_conflict")
      }
  end

  it "keeps a 422 or 402 whose code no class covers generic, with the code" do
    %w[posture_not_bound expected_unknown key_disclosure_too_low].each do |code|
      c = bg(->(*_args) { { status: 422, body: JSON.generate("error" => code, "message" => "no") } })
      expect { c.issue_challenge(ask: %w[posture]) }.to raise_error(RootHerald::HttpError) { |e|
        expect(e).not_to be_a(RootHerald::UnknownPolicyError)
        expect(e.status).to eq(422)
        expect(e.server_error).to eq(code)
        expect(e.message).to eq("no")
      }
    end
    c = bg(->(*_args) { { status: 402, body: '{"error":"plan_lapsed","message":"plan lapsed"}' } })
    expect { c.issue_challenge(ask: %w[posture]) }.to raise_error(RootHerald::HttpError) { |e|
      expect(e.status).to eq(402)
      expect(e.server_error).to eq("plan_lapsed")
    }
  end

  # ── issue_key_challenge (POST /api/v1/keys/challenge) ──

  let(:key_challenge_wire) do
    { "nonce" => "a2V5", "keyChallenge" => "rhk1c.a2V5.eyJwdXJwb3NlIjoic2lnbiJ9", "expiresAt" => "2030-01-01T00:00:00Z" }
  end

  it "issue_key_challenge posts the purpose and the expected devices with the bearer secret key" do
    seen = {}
    c = bg(recording(seen, 200, key_challenge_wire))
    kc = c.issue_key_challenge(purpose: RootHerald::Client::KEY_PURPOSE_SIGN, expected_devices: ["dev-9"])
    expect(kc).to be_a(RootHerald::Client::KeyChallenge)
    expect(kc.nonce).to eq("a2V5")
    expect(kc.key_challenge).to eq("rhk1c.a2V5.eyJwdXJwb3NlIjoic2lnbiJ9")
    expect(kc.expires_at).to eq("2030-01-01T00:00:00Z")
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/keys/challenge")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
    expect(seen[:body]).to eq("purpose" => "sign", "expectedDevices" => ["dev-9"])
  end

  it "issue_key_challenge omits expectedDevices when not supplied" do
    seen = {}
    c = bg(recording(seen, 200, key_challenge_wire))
    c.issue_key_challenge(purpose: "decrypt")
    expect(seen[:body]).to eq("purpose" => "decrypt")
  end

  it "issue_key_challenge refuses a purpose outside sign/decrypt or an empty device list locally" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.issue_key_challenge(purpose: "encrypt") }.to raise_error(ArgumentError, /purpose/)
    expect { c.issue_key_challenge(purpose: nil) }.to raise_error(ArgumentError, /purpose/)
    expect { c.issue_key_challenge }.to raise_error(ArgumentError)
    expect { c.issue_key_challenge(purpose: "sign", expected_devices: []) }
      .to raise_error(ArgumentError, /expected_devices/)
  end

  it "issue_key_challenge rejects a response without nonce, keyChallenge or expiresAt" do
    %w[nonce keyChallenge expiresAt].each do |missing|
      wire = key_challenge_wire.reject { |k, _| k == missing }
      c = bg(->(*_args) { { status: 200, body: JSON.generate(wire) } })
      expect { c.issue_key_challenge(purpose: "sign") }.to raise_error(RootHerald::HttpError, /#{missing}/)
    end
  end

  # ── certify_key (POST /api/v1/keys/certify) ──

  let(:tpm_certification) do
    { "publicArea" => "cHVi", "attest" => "YXR0", "signature" => "c2ln" }
  end

  let(:ec_certified_wire) do
    {
      "deviceId" => "dev-9", "keyId" => "key_1", "purpose" => "sign", "alg" => "ES256",
      "jwk" => { "kty" => "EC", "crv" => "P-256", "x" => "eHg", "y" => "eXk", "use" => "sig" },
      "hardwareBound" => true, "certifiedAt" => "2030-01-01T00:01:00Z"
    }
  end

  let(:rsa_certified_wire) do
    {
      "deviceId" => "dev-9", "keyId" => "key_2", "purpose" => "sign", "alg" => "RS256",
      "jwk" => { "kty" => "RSA", "n" => "bW9k", "e" => "AQAB" },
      "hardwareBound" => true, "certifiedAt" => "2030-01-01T00:01:00Z"
    }
  end

  it "certify_key relays a TPM certification under the nonce and returns the EC key" do
    seen = {}
    c = bg(recording(seen, 200, ec_certified_wire))
    key = c.certify_key(tpm_certification, nonce: "a2V5")
    expect(seen[:url]).to end_with("/api/v1/keys/certify")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
    expect(seen[:body]).to eq("nonce" => "a2V5", "certification" => tpm_certification)
    expect(key).to be_a(RootHerald::Client::CertifiedKey)
    expect(key.device_id).to eq("dev-9")
    expect(key.key_id).to eq("key_1")
    expect(key.purpose).to eq("sign")
    expect(key.alg).to eq("ES256")
    expect(key.format).to be_nil
    expect(key.jwk).to eq("kty" => "EC", "crv" => "P-256", "x" => "eHg", "y" => "eXk")
    expect(key.hardware_bound).to be(true)
    expect(key.certified_at).to eq(Time.utc(2030, 1, 1, 0, 1, 0))
    expect(key).not_to respond_to(:auth_policy)
  end

  it "certify_key returns an RSA key" do
    c = bg(->(*_args) { { status: 200, body: JSON.generate(rsa_certified_wire) } })
    key = c.certify_key(tpm_certification, nonce: "a2V5")
    expect(key.alg).to eq("RS256")
    expect(key.jwk).to eq("kty" => "RSA", "n" => "bW9k", "e" => "AQAB")
  end

  it "certify_key keeps a decrypt key's format" do
    wire = rsa_certified_wire.merge("purpose" => "decrypt", "alg" => "RSA-OAEP-256", "format" => "jwe")
    c = bg(->(*_args) { { status: 200, body: JSON.generate(wire) } })
    key = c.certify_key(tpm_certification, nonce: "a2V5")
    expect(key.purpose).to eq("decrypt")
    expect(key.format).to eq("jwe")
  end

  # The certification is per platform; the SDK checks its outer shape and
  # relays the rest untouched, future fields included.
  it "certify_key relays the macOS and iOS certification forms verbatim" do
    macos = { "platform" => "macos", "publicKey" => "cGs=", "signature" => "c2ln", "futureField" => { "a" => 1 } }
    ios = { platform: "ios", keyId: "a2lk", assertion: "Y2Jvcg" }
    [macos, ios].each do |certification|
      seen = {}
      c = bg(recording(seen, 200, ec_certified_wire.merge("hardwareBound" => false)))
      key = c.certify_key(certification, nonce: "a2V5")
      expect(seen[:body]["certification"]).to eq(JSON.parse(JSON.generate(certification)))
      expect(key.hardware_bound).to be(false)
    end
  end

  it "certify_key accepts a symbol-keyed TPM certification with extra fields" do
    seen = {}
    c = bg(recording(seen, 200, ec_certified_wire))
    certification = { publicArea: "cHVi", attest: "YXR0", signature: "c2ln", futureField: "x" }
    c.certify_key(certification, nonce: "a2V5")
    expect(seen[:body]["certification"]).to eq(
      "publicArea" => "cHVi", "attest" => "YXR0", "signature" => "c2ln", "futureField" => "x"
    )
  end

  it "certify_key validates the nonce and the certification shape before any network call" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.certify_key(tpm_certification, nonce: "") }.to raise_error(ArgumentError, /nonce/)
    expect { c.certify_key(tpm_certification, nonce: nil) }.to raise_error(ArgumentError, /nonce/)
    expect { c.certify_key({ "publicArea" => "p", "attest" => "a" }, nonce: "n") }
      .to raise_error(ArgumentError, /certification/)
    expect { c.certify_key({}, nonce: "n") }.to raise_error(ArgumentError, /certification/)
    expect { c.certify_key("not a hash", nonce: "n") }.to raise_error(ArgumentError, /certification/)
    expect { c.certify_key({ "publicArea" => "p", "attest" => "a", "signature" => 7 }, nonce: "n") }
      .to raise_error(ArgumentError, /certification/)
  end

  # The key is the call's only output: a malformed one is refused, never
  # returned half-parsed.
  it "certify_key refuses a malformed key" do
    [
      ec_certified_wire.reject { |k, _| k == "deviceId" },
      ec_certified_wire.reject { |k, _| k == "keyId" },
      ec_certified_wire.reject { |k, _| k == "hardwareBound" },
      ec_certified_wire.reject { |k, _| k == "certifiedAt" },
      ec_certified_wire.reject { |k, _| k == "jwk" },
      ec_certified_wire.merge("purpose" => "encrypt"),
      ec_certified_wire.merge("alg" => "RS256"),
      ec_certified_wire.merge("alg" => "ES384"),
      ec_certified_wire.merge("format" => "pem"),
      ec_certified_wire.merge("certifiedAt" => "yesterday"),
      ec_certified_wire.merge("jwk" => { "kty" => "EC", "crv" => "P-384", "x" => "eHg", "y" => "eXk" }),
      ec_certified_wire.merge("jwk" => { "kty" => "EC", "crv" => "P-256", "x" => "eHg" }),
      rsa_certified_wire.merge("alg" => "ES256"),
      rsa_certified_wire.merge("jwk" => { "kty" => "RSA", "n" => "bW9k" }),
      { "keyId" => "k" },
      []
    ].each do |wire|
      c = bg(->(*_args) { { status: 200, body: JSON.generate(wire) } })
      expect { c.certify_key(tpm_certification, nonce: "a2V5") }
        .to raise_error(RootHerald::HttpError, /certify response/), wire.inspect
    end
  end

  # ── relay_enroll (POST /api/v1/attest/enroll) ──

  let(:tpm_enroll_blob) do
    {
      "ekPublicKey" => "ekpub==",
      "attestationKey" => { "publicArea" => "akpub==", "parentPublicArea" => "srk==", "qualifiedName" => "qn==" },
      "platform" => "windows",
      "ekCertPem" => "-----BEGIN CERTIFICATE-----", "ekCertificateChain" => ["int=="],
      "tpmSelfReport" => { "manufacturer" => "IFX", "vendorString" => "SLB9670" }
    }
  end

  let(:tpm_enroll_wire) do
    { "enrollmentId" => "enr-1", "credentialBlob" => "cred==", "encryptedSecret" => "sec==" }
  end

  it "relay_enroll on 201 returns the TPM activation challenge, nothing else" do
    seen = {}
    c = bg(recording(seen, 201, tpm_enroll_wire))
    result = c.relay_enroll(tpm_enroll_blob)
    expect(result.challenge.enrollment_id).to eq("enr-1")
    expect(result.challenge.credential_blob).to eq("cred==")
    expect(result.challenge.encrypted_secret).to eq("sec==")
    expect(result.challenge.challenge_nonce).to be_nil
    expect(result.challenge.to_wire).to eq(tpm_enroll_wire)
    expect(result).not_to respond_to(:device_id)
    expect(result).not_to respond_to(:challenge_id)
    expect(seen[:method]).to eq(:post)
    expect(seen[:url]).to end_with("/api/v1/attest/enroll")
    expect(seen[:url]).not_to include("?")
    expect(seen[:auth]).to eq("Bearer rh_sk_test_xxx")
    expect(seen[:body]).to eq(tpm_enroll_blob)
  end

  # The body is opaque: a field this SDK has never heard of reaches the
  # server exactly as the client emitted it, nested objects included.
  it "relay_enroll relays the nested body verbatim, unknown fields included" do
    input = tpm_enroll_blob.merge(
      "platform" => "linux",
      "attestationKey" => tpm_enroll_blob["attestationKey"].merge("futureField" => { "nested" => [1, 2] }),
      "futureField" => { "a" => "b" }
    )
    symbol_keyed = {
      ekPublicKey: "ekpub==",
      attestationKey: { publicArea: "akpub==", parentPublicArea: "srk==", qualifiedName: "qn==", futureField: 1 },
      platform: :linux, futureField: [1, { x: "y" }]
    }
    [input, symbol_keyed].each do |blob|
      seen = {}
      c = bg(recording(seen, 201, tpm_enroll_wire))
      c.relay_enroll(blob)
      expect(seen[:body]).to eq(JSON.parse(JSON.generate(blob)))
    end
  end

  it "relay_enroll on 201 returns the macOS activation challenge" do
    c = bg(->(*_args) {
      { status: 201, body: JSON.generate("enrollmentId" => "enr-2", "challengeNonce" => "nonce==") }
    })
    result = c.relay_enroll("ekPublicKey" => "p256==", "akPublicArea" => "p256==", "platform" => "macos")
    expect(result.challenge.enrollment_id).to eq("enr-2")
    expect(result.challenge.challenge_nonce).to eq("nonce==")
    expect(result.challenge.credential_blob).to be_nil
    expect(result.challenge.to_wire).to eq("enrollmentId" => "enr-2", "challengeNonce" => "nonce==")
  end

  it "relay_enroll relays an iOS blob and accepts its empty 201" do
    seen = {}
    c = bg(recording(seen, 201, "{}"))
    blob = {
      "platform" => "ios", "iosKeyId" => "kid==", "iosAttestationObject" => "cbor==", "nonce" => "bm9uY2U"
    }
    result = c.relay_enroll(blob)
    expect(result.challenge).to be_nil
    expect(seen[:body]).to eq(blob)
  end

  it "relay_enroll has no challenge_id keyword and sends no query string" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.relay_enroll(tpm_enroll_blob, challenge_id: "ch_1") }.to raise_error(ArgumentError)
  end

  it "relay_enroll rejects a 201 that names no enrollment or carries no challenge" do
    [
      {},
      { "credentialBlob" => "cred==", "encryptedSecret" => "sec==" },
      { "enrollmentId" => "enr-1" },
      { "enrollmentId" => "enr-1", "credentialBlob" => "cred==" },
      { "enrollmentId" => 7, "challengeNonce" => "n==" }
    ].each do |wire|
      c = bg(->(*_args) { { status: 201, body: JSON.generate(wire) } })
      expect { c.relay_enroll(tpm_enroll_blob) }.to raise_error(RootHerald::HttpError, /enrollmentId/)
    end
  end

  it "relay_enroll maps a 422 admission_refused to AdmissionRefusedError" do
    c = bg(->(*_args) {
      { status: 422, body: '{"error":"admission_refused","detail":"firmware TPM under a discrete-only policy"}' }
    })
    expect { c.relay_enroll(tpm_enroll_blob) }
      .to raise_error(RootHerald::AdmissionRefusedError) { |e|
        expect(e.code).to eq("admission_refused")
        expect(e.server_error).to eq("admission_refused")
        expect(e.message).to eq("firmware TPM under a discrete-only policy")
      }
  end

  # A flat TPM body is the 7.0 shape. The server would answer
  # wire_version_unsupported; refusing it here keeps the message specific and
  # spends nothing.
  it "relay_enroll refuses a flat 7.0 TPM blob locally, before any request" do
    c = bg(->(*_args) { raise "should not be called" })
    flat = { "ekPublicKey" => "ekpub==", "akPublicArea" => "akpub==", "platform" => "windows" }
    expect { c.relay_enroll(flat) }.to raise_error(ArgumentError, /attestationKey/)
    expect { c.relay_enroll(flat.merge("platform" => "linux")) }.to raise_error(ArgumentError, /attestationKey/)
    both = tpm_enroll_blob.merge("akPublicArea" => "akpub==")
    expect { c.relay_enroll(both) }.to raise_error(ArgumentError)
  end

  it "relay_enroll validates each platform's shape before any network call" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.relay_enroll({}) }.to raise_error(ArgumentError)
    expect { c.relay_enroll("not a hash") }.to raise_error(ArgumentError)
    expect { c.relay_enroll(tpm_enroll_blob.reject { |k, _| k == "platform" }) }.to raise_error(ArgumentError)
    expect { c.relay_enroll(tpm_enroll_blob.merge("platform" => "android")) }.to raise_error(ArgumentError)
    expect { c.relay_enroll(tpm_enroll_blob.reject { |k, _| k == "ekPublicKey" }) }.to raise_error(ArgumentError)
    %w[publicArea parentPublicArea qualifiedName].each do |missing|
      ak = tpm_enroll_blob["attestationKey"].reject { |k, _| k == missing }
      expect { c.relay_enroll(tpm_enroll_blob.merge("attestationKey" => ak)) }.to raise_error(ArgumentError)
    end
    expect { c.relay_enroll("ekPublicKey" => "e", "platform" => "macos") }.to raise_error(ArgumentError)
    nested_mac = { "ekPublicKey" => "e", "akPublicArea" => "a", "platform" => "macos",
                   "attestationKey" => tpm_enroll_blob["attestationKey"] }
    expect { c.relay_enroll(nested_mac) }.to raise_error(ArgumentError)
    expect { c.relay_enroll("platform" => "ios", "iosKeyId" => "k", "iosAttestationObject" => "a") }
      .to raise_error(ArgumentError, /nonce/)
  end

  it "relay_enroll accepts symbol-keyed blobs" do
    c = bg(->(*_args) { { status: 201, body: JSON.generate(tpm_enroll_wire) } })
    result = c.relay_enroll(ekPublicKey: "e", platform: "windows",
                            attestationKey: { publicArea: "a", parentPublicArea: "p", qualifiedName: "q" })
    expect(result.challenge.enrollment_id).to eq("enr-1")
    c = bg(->(*_args) { { status: 201, body: "{}" } })
    expect(c.relay_enroll(platform: "ios", iosKeyId: "k", iosAttestationObject: "a", nonce: "n").challenge).to be_nil
  end

  it "relay_enroll maps a 401 to InvalidSecretKeyError" do
    c = bg(->(*_args) { { status: 401, body: '{"message":"nope"}' } })
    expect { c.relay_enroll(tpm_enroll_blob) }
      .to raise_error(RootHerald::InvalidSecretKeyError)
  end

  it "relay_enroll maps a 400 wire_version_unsupported to InvalidEvidenceError with the code" do
    c = bg(->(*_args) { { status: 400, body: '{"error":"wire_version_unsupported","message":"7.0 body"}' } })
    expect { c.relay_enroll(tpm_enroll_blob) }
      .to raise_error(RootHerald::InvalidEvidenceError) { |e|
        expect(e.server_error).to eq("wire_version_unsupported")
      }
  end

  # ── relay_activate (POST /api/v1/attest/activate) ──

  it "relay_activate relays the decrypted secret and returns the device" do
    seen = {}
    c = bg(recording(seen, 200,
                     "deviceId" => "dev-1", "status" => "enrolled", "enrolledAt" => "2030-01-01T00:00:00Z"))
    result = c.relay_activate("enrollmentId" => "enr-1", "decryptedSecret" => "secret==")
    expect(result.device_id).to eq("dev-1")
    expect(result.status).to eq("enrolled")
    expect(result.enrolled_at).to eq("2030-01-01T00:00:00Z")
    expect(seen[:url]).to end_with("/api/v1/attest/activate")
    expect(seen[:url]).not_to include("?")
    expect(seen[:body]).to eq("enrollmentId" => "enr-1", "decryptedSecret" => "secret==")
  end

  it "relay_activate relays a macOS signature" do
    seen = {}
    c = bg(recording(seen, 200, "deviceId" => "dev-2", "status" => "enrolled"))
    result = c.relay_activate(enrollmentId: "enr-2", signature: "sig==")
    expect(result.device_id).to eq("dev-2")
    expect(seen[:body]).to eq("enrollmentId" => "enr-2", "signature" => "sig==")
  end

  it "relay_activate validates required blob fields" do
    c = bg(->(*_args) { raise "should not be called" })
    expect { c.relay_activate("enrollmentId" => "enr-1") }.to raise_error(ArgumentError)
    expect { c.relay_activate("enrollmentId" => "", "decryptedSecret" => "s") }.to raise_error(ArgumentError)
    expect { c.relay_activate("decryptedSecret" => "s") }.to raise_error(ArgumentError)
    expect { c.relay_activate("deviceId" => "d", "decryptedSecret" => "s") }.to raise_error(ArgumentError)
  end

  it "relay_activate maps a 409 to ChallengeError" do
    c = bg(->(*_args) { { status: 409, body: '{"message":"stale"}' } })
    expect { c.relay_activate("enrollmentId" => "enr-1", "decryptedSecret" => "s") }
      .to raise_error(RootHerald::ChallengeError)
  end

  it "relay_activate maps a refusal to ActivationRefusedError, not InvalidSecretKeyError" do
    c = bg(->(*_args) { { status: 401, body: '{"error":"activation_refused","message":"Invalid credential activation response"}' } })
    expect { c.relay_activate("enrollmentId" => "enr-1", "decryptedSecret" => "wrong") }
      .to raise_error(RootHerald::ActivationRefusedError)
    c = bg(->(*_args) { { status: 401, body: '{"error":"invalid_secret_key"}' } })
    expect { c.relay_activate("enrollmentId" => "enr-1", "decryptedSecret" => "s") }
      .to raise_error(RootHerald::InvalidSecretKeyError)
  end
end
