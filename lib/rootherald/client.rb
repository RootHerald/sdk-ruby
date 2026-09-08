# frozen_string_literal: true

require "cgi"
require "ipaddr"
require "json"
require "time"
require "uri"

module RootHerald
  # Server -> server Background-Check client.
  #
  # The customer's keyless client collects opaque blobs (no keys, no Root Herald
  # contact) and hands them to the customer's own server. The server uses this
  # client, authenticated with its +rh_sk_+ secret key, to relay them to Root
  # Herald. It mirrors @rootherald/node's four backend helpers:
  #   1. #relay_enroll    — POST /api/v1/attest/enroll
  #   2. #relay_activate  — POST /api/v1/attest/activate
  #   3. #issue_challenge — POST /api/v1/attest/challenge (a challenge carrying the ask)
  #   4. #verify          — POST /api/v1/attest/verify     (appraise → verdict)
  #
  # The verdict is computed by Root Herald and returned to the backend — it never
  # travels through the keyless client.
  class Client
    DEFAULT_BASE_URL = "https://rootherald.io"
    SECRET_KEY_PREFIX = "rh_sk_"

    # Ask: prove which enrolled device this is.
    ASK_IDENTITY = "identity"
    # Ask: prove the boot / configuration state (quote + event log).
    ASK_POSTURE = "posture"
    # Ask: certify a fresh TPM-resident signing key under the AK.
    ASK_KEY = "key"
    # The only key purpose today.
    KEY_PURPOSE_SIGN = "sign"

    # A challenge minted by #issue_challenge. Relay +challenge+ to the client
    # verbatim; it carries the nonce and the ask the server bound to it.
    # +challenge+ is nil when the server omitted it.
    Challenge = Struct.new(:challenge_id, :challenge, :nonce, :expires_at, keyword_init: true)

    # A TPM-resident signing key the appraisal certified; +AttestResult#key+
    # when the challenge asked for "key" and the verdict passed. +jwk+ is the
    # public key as a Hash (kty "EC", crv "P-256" | "P-384", base64url x / y);
    # +certified_at+ is a Time. Verify later device signatures with
    # +RootHerald::KeySignatures.verify+.
    CertifiedKey = Struct.new(:key_id, :jwk, :purpose, :auth_policy, :certified_at, keyword_init: true)

    # The MakeCredential challenge — the +201+ response body of
    # POST /api/v1/attest/enroll. +credential_blob+ / +encrypted_secret+ are the
    # TPM2_MakeCredential outputs the client feeds into TPM2_ActivateCredential
    # (its +EnrollComplete+ leg).
    EnrollChallenge = Struct.new(:device_id, :credential_blob, :encrypted_secret, keyword_init: true)

    # Result of the enroll-relay leg (#relay_enroll), mirroring
    # @rootherald/node's +RelayEnrollResult+.
    #
    # Enrollment always issues a challenge, including for a device already known —
    # re-enrollment is how a device rotates its attestation key, so
    # short-circuiting it would make rotation impossible. Relay +challenge+ to
    # the client's +EnrollComplete+, then call #relay_activate.
    #
    # +device_id+ is THIS tenant's alias for the device, not a global identifier:
    # another tenant enrolling the same silicon is told a different one.
    # +challenge_id+ is the attestation challenge the enrollment was admitted
    # against, when the server echoed one; nil otherwise.
    RelayEnrollResult = Struct.new(:device_id, :challenge, :challenge_id, keyword_init: true)

    # The terminal response of the activate-relay leg (#relay_activate) —
    # POST /api/v1/attest/activate. +device_id+ is the load-bearing field the
    # backend maps to its user.
    ActivateResult = Struct.new(:device_id, :status, :enrolled_at, keyword_init: true)

    # The result of #verify: the device verdict and the full verdict data.
    #
    # +assurance_claims_met+ / +enrollment_required+ mirror @rootherald/node:
    # the top-level +assuranceClaimsMet+ (satisfied assurance URNs) and
    # +enrollment_required+ (the attest-first / enroll-on-miss signal).
    # +key+ is the CertifiedKey from the top-level +key+, present only on a
    # passing verdict for a challenge that asked for "key"; nil otherwise.
    #
    # The cohort accessors expose the ADDITIVE, advisory-only cohort fields the
    # server populates on +verdict_data["device"]+ (camelCase keys) when a
    # quote-bound event log was supplied — never a trust gate. They return nil
    # (or {} for the per-PCR map) when the server omitted them.
    AttestResult = Struct.new(:verdict, :verdict_data, :assurance_claims_met, :enrollment_required, :key,
                              keyword_init: true) do
      # @return [Hash] the raw +device+ sub-object, passed through verbatim
      def device
        d = verdict_data.is_a?(Hash) ? verdict_data["device"] : nil
        d.is_a?(Hash) ? d : {}
      end

      # @return [String, nil] opaque cohort key
      def cohort_key
        v = device["cohortKey"]
        v.is_a?(String) ? v : nil
      end

      # @return [String, nil] cohort scope ("global" | "tenant-fleet")
      def cohort_scope
        v = device["cohortScope"]
        v.is_a?(String) ? v : nil
      end

      # @return [Float, nil] fraction of the cohort sharing this profile
      def cohort_prevalence
        v = device["cohortPrevalence"]
        v.is_a?(Numeric) ? v.to_f : nil
      end

      # @return [Hash{String=>Float}] per-PCR prevalence map; {} if absent
      def cohort_prevalence_per_pcr
        v = device["cohortPrevalencePerPcr"]
        return {} unless v.is_a?(Hash)

        v.each_with_object({}) do |(pcr, frac), acc|
          acc[pcr.to_s] = frac.to_f if frac.is_a?(Numeric)
        end
      end

      # @return [Integer, nil] number of devices in the cohort sample
      def cohort_sample_size
        v = device["cohortSampleSize"]
        v.is_a?(Integer) ? v : nil
      end

      # @return [Boolean, nil] whether this is a previously-unseen profile
      def novel_profile
        v = device["novelProfile"]
        [true, false].include?(v) ? v : nil
      end
    end

    # @param secret_key [String] your Root Herald secret key (rh_sk_…); required
    # @param base_url [String]
    # @param timeout_seconds [Float]
    # @param http_transport [#call, nil] callable taking
    #        +(method, url, headers, body)+ and returning +{status:, body:}+
    # @raise [ArgumentError] if the key is empty, is not an rh_sk_ key, or the
    #   base URL is not https (loopback excepted)
    def initialize(secret_key:, base_url: DEFAULT_BASE_URL,
                   timeout_seconds: 10.0, http_transport: nil)
      raise ArgumentError, "a secret key (rh_sk_…) is required" if secret_key.nil? || secret_key.empty?
      unless secret_key.start_with?(SECRET_KEY_PREFIX)
        raise ArgumentError,
              "RootHerald secret key must start with rh_sk_"
      end

      @secret_key = secret_key
      @base_url = self.class.require_secure_base_url(base_url)
      @timeout = timeout_seconds
      @http_transport = http_transport || build_default_transport
    end

    # Reject a base URL that would put the +rh_sk_+ secret on the wire in the
    # clear.
    #
    # The secret rides in an Authorization header on every request and is
    # full-privilege, so an +http://+ or scheme-less base URL hands it to anyone
    # on the path. A typo is enough, and nothing downstream notices, because the
    # request itself still succeeds.
    #
    # Loopback is excepted so the local docker stack keeps working over http.
    #
    # @param base_url [String]
    # @return [String] the normalised base URL
    # @raise [ArgumentError] when the URL is not absolute https or loopback
    def self.require_secure_base_url(base_url)
      raw = base_url.to_s.chomp("/")
      uri = begin
        URI.parse(raw)
      rescue URI::InvalidURIError
        nil
      end

      if uri.nil? || uri.host.nil? || uri.scheme.nil?
        raise ArgumentError, "base_url must be an absolute https URL (got #{raw.inspect})"
      end
      return raw if uri.scheme == "https"
      return raw if loopback_host?(uri.host)

      raise ArgumentError, "base_url must use https (got #{raw.inspect})"
    end

    # @api private
    def self.loopback_host?(host)
      stripped = host.delete_prefix("[").delete_suffix("]")
      return true if stripped == "localhost"

      begin
        IPAddr.new(stripped).loopback?
      rescue IPAddr::InvalidAddressError
        false
      end
    end

    # Enroll relay — leg 1. POST /api/v1/attest/enroll.
    #
    # Relays the client's +EnrollBegin()+ blob to Root Herald with the +rh_sk_+
    # secret and returns the challenge to hand back to the client's
    # +EnrollComplete+, whose result goes to #relay_activate.
    #
    # The client never holds the +rh_sk_+ key and never talks to Root Herald;
    # this backend helper is the only thing that does.
    #
    # Pass a live +challenge_id+ from #issue_challenge to run admission against
    # the policy stored on that challenge instead of the tenant default; a
    # device that could never satisfy it is refused before it gets an AK
    # (AdmissionRefusedError, 422 admission_refused).
    #
    # @param enroll_request_blob [Hash] the opaque +EnrollBegin()+ blob from the
    #        client, relayed verbatim. Wire shape (camelCase keys): +ekPublicKey+,
    #        +akPublicArea+ (required), +platform+, +ekCertPem+,
    #        +ekCertificateChain+. String or symbol keys are accepted.
    # @param challenge_id [String, nil] sent as the +challengeId+ query
    #        parameter; omitted when nil
    # @return [RelayEnrollResult]
    # @raise [ArgumentError] if the blob lacks ekPublicKey/akPublicArea
    def relay_enroll(enroll_request_blob = nil, challenge_id: nil, **symbol_keyed_blob)
      # A braceless symbol-keyed blob (+relay_enroll(ekPublicKey: ..., ...)+)
      # arrives as keywords now that the method has one of its own.
      enroll_request_blob = symbol_keyed_blob if enroll_request_blob.nil?
      ek = blob_field(enroll_request_blob, "ekPublicKey")
      ak = blob_field(enroll_request_blob, "akPublicArea")
      unless ek.is_a?(String) && ak.is_a?(String)
        raise ArgumentError,
              "relay_enroll requires an enroll request blob with ekPublicKey and akPublicArea"
      end

      path = "/api/v1/attest/enroll"
      path += "?challengeId=#{CGI.escape(challenge_id)}" unless challenge_id.nil? || challenge_id.empty?
      status, body = raw_post(path, enroll_request_blob)

      raise map_error(status, body) if status >= 400

      data = parse_object(status, body)
      device_id = data["deviceId"]
      credential_blob = data["credentialBlob"]
      encrypted_secret = data["encryptedSecret"]
      unless device_id.is_a?(String) && credential_blob.is_a?(String) && encrypted_secret.is_a?(String)
        raise HttpError.new(status, body, "enroll response missing deviceId/credentialBlob/encryptedSecret")
      end

      RelayEnrollResult.new(
        device_id: device_id,
        challenge: EnrollChallenge.new(
          device_id: device_id,
          credential_blob: credential_blob,
          encrypted_secret: encrypted_secret
        ),
        challenge_id: data["challengeId"].is_a?(String) ? data["challengeId"] : nil
      )
    end

    # Enroll relay — leg 2. POST /api/v1/attest/activate.
    #
    # Relays the client's +EnrollComplete()+ blob (the decrypted credential
    # secret) to Root Herald, completing the EK→AK credential-activation
    # handshake, with the blob the client produced from #relay_enroll's challenge.
    #
    # @param activation_response [Hash] the opaque +EnrollComplete()+ blob,
    #        relayed verbatim. Wire shape (camelCase keys): +deviceId+,
    #        +decryptedSecret+ (required), +akPublicKey+ (optional). String or
    #        symbol keys are accepted.
    # @return [ActivateResult] +device_id+ is the load-bearing field
    # @raise [ArgumentError] if the blob lacks deviceId/decryptedSecret
    def relay_activate(activation_response)
      device_id = blob_field(activation_response, "deviceId")
      decrypted_secret = blob_field(activation_response, "decryptedSecret")
      unless device_id.is_a?(String) && !device_id.empty? && decrypted_secret.is_a?(String)
        raise ArgumentError,
              "relay_activate requires an activation response with deviceId and decryptedSecret"
      end

      data = post("/api/v1/attest/activate", activation_response)
      out_device_id = data["deviceId"]
      raise HttpError.new(200, data.to_json, "activate response missing deviceId") unless out_device_id.is_a?(String)

      ActivateResult.new(
        device_id: out_device_id,
        status: data["status"].is_a?(String) ? data["status"] : nil,
        enrolled_at: data["enrolledAt"].is_a?(String) ? data["enrolledAt"] : nil
      )
    end

    # POST /api/v1/attest/challenge — mint a challenge that carries the ask.
    # Relay +challenge.challenge+ to the client verbatim; it quotes over it,
    # then submit the resulting evidence with #verify using the returned
    # challenge_id.
    #
    # What the device must prove is fixed here, not at verify time: a policy
    # named on the challenge is stored with it, and verify may only tighten it.
    #
    # @param device_hint [String, nil] optional advisory device hint
    # @param ask [Array<String>, nil] any of ASK_IDENTITY / ASK_POSTURE /
    #        ASK_KEY; nil or empty means the server default, identity + posture
    # @param policy [String, nil] tenant policy id/name or a
    #        "rootherald:builtin:*" name, bound to the challenge
    # @param key_purpose [String, nil] purpose of the certified key when asking
    #        for ASK_KEY (KEY_PURPOSE_SIGN)
    # @return [Challenge]
    def issue_challenge(device_hint: nil, ask: nil, policy: nil, key_purpose: nil)
      body = {}
      body["deviceHint"] = device_hint unless device_hint.nil?
      body["ask"] = Array(ask).map(&:to_s) unless ask.nil? || Array(ask).empty?
      body["policy"] = policy unless policy.nil?
      body["keyPurpose"] = key_purpose unless key_purpose.nil?
      data = post("/api/v1/attest/challenge", body)
      unless data["challengeId"] && data["nonce"] && data["expiresAt"]
        raise HttpError.new(200, data.to_json, "challenge response missing challengeId/nonce/expiresAt")
      end

      Challenge.new(
        challenge_id: data["challengeId"],
        challenge: data["challenge"].is_a?(String) ? data["challenge"] : nil,
        nonce: data["nonce"],
        expires_at: data["expiresAt"]
      )
    end

    # POST /api/v1/attest/verify — submit the opaque evidence blob for
    # server-side appraisal and return the verdict.
    #
    # An un-enrolled / failing device is NOT an error — it returns a normal
    # AttestResult carrying +:deny+/+:warn+. Only protocol/auth/quota problems
    # raise.
    #
    # The verdict is computed by Root Herald and returned here, to the customer's
    # backend — it never travels through the keyless client.
    #
    # @param evidence [Hash, Array, String] opaque blob from the client collector; passed through verbatim
    # @param challenge_id [String] the single-use id from #issue_challenge
    # @param policy [String, nil] tenant policy id/name or a "rootherald:builtin:*"
    #        name; unknown names fail closed (422). When the challenge was issued
    #        with a policy this may only name one at least as strict; a looser
    #        one is refused with PolicyDowngradeError (422 policy_downgrade)
    # @param requested_disclosure_class [String, nil] optional disclosure ceiling
    #        ("verdict" | "pseudonymous" | "derived" | "full"); omitted from the
    #        request body when nil
    # @return [AttestResult]
    def verify(evidence, challenge_id:, policy: nil, requested_disclosure_class: nil)
      raise ChallengeError.new(409, "", "verify requires challenge_id (from issue_challenge)") if challenge_id.to_s.empty?

      body = { "challengeId" => challenge_id, "evidence" => evidence }
      body["policy"] = policy unless policy.nil?
      body["requestedDisclosureClass"] = requested_disclosure_class unless requested_disclosure_class.nil?

      data = post("/api/v1/attest/verify", body)
      verdict_data = data["verdict"]
      raise HttpError.new(200, data.to_json, "verify response missing verdict") unless verdict_data.is_a?(Hash)

      device = verdict_data["device"].is_a?(Hash) ? verdict_data["device"] : {}
      AttestResult.new(
        verdict: Verdict.from_raw(device["verdict"]),
        verdict_data: verdict_data,
        assurance_claims_met: data["assuranceClaimsMet"].is_a?(Array) ? data["assuranceClaimsMet"] : [],
        enrollment_required: data["enrollmentRequired"] == true,
        # `key` is a top-level sibling too, present only on a passing verdict
        # for a challenge that asked for a key.
        key: data["key"].nil? ? nil : parse_certified_key(data)
      )
    end

    private

    def parse_certified_key(data)
      node = data["key"]
      jwk = node.is_a?(Hash) ? node["jwk"] : nil
      well_formed = node.is_a?(Hash) && jwk.is_a?(Hash) &&
                    node["keyId"].is_a?(String) && node["certifiedAt"].is_a?(String) &&
                    %w[kty crv x y].all? { |f| jwk[f].is_a?(String) }
      raise HttpError.new(200, data.to_json, "verify response key missing keyId/jwk/certifiedAt") unless well_formed

      certified_at = begin
        Time.iso8601(node["certifiedAt"])
      rescue ArgumentError
        raise HttpError.new(200, data.to_json, "verify response key.certifiedAt is not a timestamp")
      end

      CertifiedKey.new(
        key_id: node["keyId"],
        jwk: jwk.slice("kty", "crv", "x", "y"),
        purpose: node["purpose"].is_a?(String) ? node["purpose"] : nil,
        auth_policy: node["authPolicy"].is_a?(String) ? node["authPolicy"] : nil,
        certified_at: certified_at
      )
    end

    # Authenticated JSON POST; maps non-2xx to a typed error and parses the body.
    def post(path, body)
      status, resp_body = raw_post(path, body)
      raise map_error(status, resp_body) if status >= 400

      parse_object(status, resp_body)
    end

    # Authenticated JSON POST returning +[status, body]+ verbatim, leaving status
    # interpretation to the caller. +path+ may carry a query string.
    def raw_post(path, body)
      url = "#{@base_url}#{path}"
      headers = {
        "Authorization" => "Bearer #{@secret_key}",
        "Content-Type" => "application/json",
        "Accept" => "application/json"
      }
      resp = @http_transport.call(:post, url, headers, JSON.generate(body))
      [resp[:status] || resp["status"], (resp[:body] || resp["body"] || "").to_s]
    end

    # Parse a 2xx response body into a Hash. An empty/204 body is +{}+; a non-Hash
    # JSON value is wrapped as +{ "value" => ... }+.
    def parse_object(status, resp_body)
      return {} if status == 204 || resp_body.to_s.empty?

      begin
        decoded = JSON.parse(resp_body)
      rescue JSON::ParserError => e
        raise HttpError.new(status, resp_body, "non-JSON response: #{e.message}")
      end
      decoded.is_a?(Hash) ? decoded : { "value" => decoded }
    end

    # Read a wire-shape field from an opaque client blob, accepting either string
    # or symbol keys so a backend can relay either a JSON-parsed Hash or a
    # symbol-keyed Ruby Hash verbatim.
    def blob_field(blob, key)
      return nil unless blob.is_a?(Hash)

      blob.key?(key) ? blob[key] : blob[key.to_sym]
    end

    # Map a non-2xx status to the matching typed error, mirroring
    # @rootherald/node. A 422 is split on the server's +error+ code:
    # policy_downgrade and admission_refused get their own classes; anything
    # else is the policy-resolution failure.
    def map_error(status, body)
      message = nil
      code = nil
      begin
        parsed = JSON.parse(body)
        if parsed.is_a?(Hash)
          message = %w[message detail error_description].map { |f| parsed[f] }.find { |v| v.is_a?(String) }
          code = [parsed["error"], parsed["code"]].find { |v| v.is_a?(String) }
        end
      rescue JSON::ParserError
        # non-JSON body; fall through to status-based message
      end

      klass = case status
              when 401 then InvalidSecretKeyError
              when 422
                case code
                when "policy_downgrade" then PolicyDowngradeError
                when "admission_refused" then AdmissionRefusedError
                else UnknownPolicyError
                end
              when 409 then ChallengeError
              when 400 then InvalidEvidenceError
              when 429 then QuotaExceededError
              else HttpError
              end
      klass.new(status, body, message, code)
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
