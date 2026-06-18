# frozen_string_literal: true

require "json"

module RootHerald
  # Server -> server Background-Check client.
  #
  # The customer's dumb client collects an opaque evidence blob (no keys, no
  # Root Herald contact) and hands it to the customer's own server. The server
  # uses this client, authenticated with its +rh_sk_+ secret key, to:
  #   1. mint a relay-friendly nonce  (#create_challenge)
  #   2. submit the evidence for appraisal and get a verdict  (#attest)
  #
  # This is ADDITIVE. The offline/badge-tier path (RootHerald::Client#verify_token
  # / RootHerald::Guard) is unchanged; the optional token returned by
  # +attest(..., return_token: true)+ is itself verifiable with it.
  class BackgroundCheck
    DEFAULT_BASE_URL = "https://api.rootherald.com"
    SECRET_KEY_PREFIX = "rh_sk_"

    # A relay-friendly nonce minted by #create_challenge.
    Challenge = Struct.new(:challenge_id, :nonce, :expires_at, keyword_init: true)

    # The result of #attest: the device verdict, the full verdict data, and an
    # optional signed EAT (JWT) when +return_token: true+ was requested.
    AttestResult = Struct.new(:verdict, :verdict_data, :token, keyword_init: true)

    # @param secret_key [String] your Root Herald secret key (rh_sk_…); required
    # @param base_url [String]
    # @param timeout_seconds [Float]
    # @param http_transport [#call, nil] callable taking
    #        +(method, url, headers, body)+ and returning +{status:, body:}+
    # @raise [ArgumentError] if the key is empty or not an rh_sk_ key
    def initialize(secret_key:, base_url: DEFAULT_BASE_URL,
                   timeout_seconds: 10.0, http_transport: nil)
      raise ArgumentError, "a secret key (rh_sk_…) is required" if secret_key.nil? || secret_key.empty?
      unless secret_key.start_with?(SECRET_KEY_PREFIX)
        raise ArgumentError,
              "secret_key must be a secret key (rh_sk_…); a publishable key (rh_pk_…) must never be used server-side"
      end

      @secret_key = secret_key
      @base_url = base_url.to_s.chomp("/")
      @timeout = timeout_seconds
      @http_transport = http_transport || build_default_transport
    end

    # POST /api/v1/attestations/challenge — mint a relay-friendly nonce. Relay
    # the nonce to the client; the client quotes over it, then submit the
    # resulting evidence with #attest using the returned challenge_id.
    #
    # @param device_hint [String, nil] optional advisory device hint
    # @return [Challenge]
    def create_challenge(device_hint: nil)
      body = {}
      body["deviceHint"] = device_hint unless device_hint.nil?
      data = post("/api/v1/attestations/challenge", body)
      unless data["challengeId"] && data["nonce"] && data["expiresAt"]
        raise HttpError.new(200, data.to_json, "challenge response missing challengeId/nonce/expiresAt")
      end

      Challenge.new(
        challenge_id: data["challengeId"],
        nonce: data["nonce"],
        expires_at: data["expiresAt"]
      )
    end

    # POST /api/v1/attestations/verify — submit the opaque evidence blob for
    # server-side appraisal and return the verdict (plus an optional signed EAT
    # when +return_token: true+).
    #
    # An un-enrolled / failing device is NOT an error — it returns a normal
    # AttestResult carrying +:deny+/+:warn+. Only protocol/auth/quota problems
    # raise.
    #
    # @param evidence [Hash, Array, String] opaque blob from the client collector; passed through verbatim
    # @param challenge_id [String] the single-use id from #create_challenge
    # @param policy [String, nil] tenant policy id/name or a "rootherald:builtin:*" name; unknown names fail closed (422)
    # @param return_token [Boolean] opt-in signed EAT (JWT) output
    # @return [AttestResult]
    def attest(evidence, challenge_id:, policy: nil, return_token: false)
      raise ChallengeError.new(409, "", "attest requires challenge_id (from create_challenge)") if challenge_id.to_s.empty?

      body = { "challengeId" => challenge_id, "evidence" => evidence }
      body["policy"] = policy unless policy.nil?
      body["returnToken"] = true if return_token

      data = post("/api/v1/attestations/verify", body)
      verdict_data = data["verdict"]
      raise HttpError.new(200, data.to_json, "verify response missing verdict") unless verdict_data.is_a?(Hash)

      AttestResult.new(
        verdict: Verdict.from_raw(verdict_data["verdict"]),
        verdict_data: verdict_data,
        token: data["token"].is_a?(String) ? data["token"] : nil
      )
    end

    private

    def post(path, body)
      url = "#{@base_url}#{path}"
      headers = {
        "Authorization" => "Bearer #{@secret_key}",
        "Content-Type" => "application/json",
        "Accept" => "application/json"
      }
      resp = @http_transport.call(:post, url, headers, JSON.generate(body))
      status = resp[:status] || resp["status"]
      resp_body = resp[:body] || resp["body"] || ""

      raise map_error(status, resp_body) if status >= 400
      return {} if status == 204 || resp_body.to_s.empty?

      begin
        decoded = JSON.parse(resp_body)
      rescue JSON::ParserError => e
        raise HttpError.new(status, resp_body, "non-JSON response: #{e.message}")
      end
      decoded.is_a?(Hash) ? decoded : { "value" => decoded }
    end

    # Map a non-2xx status to the matching typed error, mirroring @rootherald/node.
    def map_error(status, body)
      message = nil
      begin
        parsed = JSON.parse(body)
        message = parsed["message"] || parsed["error_description"] if parsed.is_a?(Hash)
      rescue JSON::ParserError
        # non-JSON body; fall through to status-based message
      end

      klass = {
        401 => InvalidSecretKeyError,
        422 => UnknownPolicyError,
        409 => ChallengeError,
        400 => InvalidEvidenceError,
        429 => QuotaExceededError
      }.fetch(status, HttpError)
      klass.new(status, body, message)
    end

    def build_default_transport
      require "faraday"
      conn = Faraday.new do |f|
        f.options.timeout = @timeout
      end
      lambda do |method, url, headers, body|
        resp = conn.run_request(method, url, body, headers)
        { status: resp.status, body: resp.body.to_s }
      end
    end
  end
end
