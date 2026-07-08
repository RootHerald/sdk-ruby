# frozen_string_literal: true

require "json"

module RootHerald
  # Server -> server Background-Check client.
  #
  # The customer's keyless client collects opaque blobs (no keys, no Root Herald
  # contact) and hands them to the customer's own server. The server uses this
  # client, authenticated with its +rh_sk_+ secret key, to relay them to Root
  # Herald. It mirrors @rootherald/node's four backend helpers:
  #   1. #relay_enroll    — POST /api/v1/devices/enroll   (201 fresh / 409 bound)
  #   2. #relay_activate  — POST /api/v1/devices/activate
  #   3. #issue_challenge — POST /api/v1/attestations/challenge (relay-friendly nonce)
  #   4. #verify          — POST /api/v1/attestations/verify     (appraise → verdict)
  #
  # The verdict is computed by Root Herald and returned to the backend — it never
  # travels through the keyless client.
  class BackgroundCheck
    DEFAULT_BASE_URL = "https://api.rootherald.io"
    SECRET_KEY_PREFIX = "rh_sk_"

    # A relay-friendly nonce minted by #issue_challenge.
    Challenge = Struct.new(:challenge_id, :nonce, :expires_at, keyword_init: true)

    # The MakeCredential challenge — the +201+ response body of
    # POST /api/v1/devices/enroll. +credential_blob+ / +encrypted_secret+ are the
    # TPM2_MakeCredential outputs the client feeds into TPM2_ActivateCredential
    # (its +EnrollComplete+ leg).
    EnrollChallenge = Struct.new(:device_id, :credential_blob, :encrypted_secret, keyword_init: true)

    # Resolved result of the enroll-relay leg (#relay_enroll), normalizing the
    # asymmetric +201+/+409+ HTTP outcomes into one shape so callers branch on
    # #already_enrolled? instead of re-parsing the HTTP status — mirroring
    # @rootherald/node's +RelayEnrollResult+.
    #
    # * +already_enrolled == false+ — fresh +201+ enroll: +challenge+ (an
    #   {EnrollChallenge}) is present; relay it to the client's +EnrollComplete+,
    #   then call #relay_activate.
    # * +already_enrolled == true+ — +409+ short-circuit: the device is already
    #   bound, so SKIP the activate leg and just use +device_id+. No +challenge+.
    #
    # Either way +device_id+ is resolved.
    RelayEnrollResult = Struct.new(:already_enrolled, :device_id, :challenge, keyword_init: true) do
      # @return [Boolean] true when the device was already enrolled (409)
      def already_enrolled? = already_enrolled == true
    end

    # The terminal response of the activate-relay leg (#relay_activate) —
    # POST /api/v1/devices/activate. +device_id+ is the load-bearing field the
    # backend maps to its user.
    ActivateResult = Struct.new(:device_id, :status, :enrolled_at, keyword_init: true)

    # The result of #verify: the device verdict and the full verdict data.
    #
    # The cohort accessors expose the ADDITIVE, advisory-only cohort fields the
    # server populates on +verdict_data["device"]+ (camelCase keys) when a
    # quote-bound event log was supplied — never a trust gate. They return nil
    # (or {} for the per-PCR map) when the server omitted them.
    AttestResult = Struct.new(:verdict, :verdict_data, keyword_init: true) do
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
    # @raise [ArgumentError] if the key is empty or not an rh_sk_ key
    def initialize(secret_key:, base_url: DEFAULT_BASE_URL,
                   timeout_seconds: 10.0, http_transport: nil)
      raise ArgumentError, "a secret key (rh_sk_…) is required" if secret_key.nil? || secret_key.empty?
      unless secret_key.start_with?(SECRET_KEY_PREFIX)
        raise ArgumentError,
              "RootHerald secret key must start with rh_sk_"
      end

      @secret_key = secret_key
      @base_url = base_url.to_s.chomp("/")
      @timeout = timeout_seconds
      @http_transport = http_transport || build_default_transport
    end

    # Enroll relay — leg 1. POST /api/v1/devices/enroll.
    #
    # Relays the client's +EnrollBegin()+ blob to Root Herald with the +rh_sk_+
    # secret and resolves the asymmetric response:
    #
    # * +201+ — a fresh enroll: returns a {RelayEnrollResult} with
    #   +already_enrolled == false+ and +challenge+ (an {EnrollChallenge}). Hand
    #   +challenge+ to the client's +EnrollComplete+, then relay the result to
    #   #relay_activate.
    # * +409+ — the device is already enrolled: returns a {RelayEnrollResult}
    #   with +already_enrolled == true+ and only +device_id+ (no challenge). SKIP
    #   the activate leg — the device is already bound; just use +device_id+.
    #
    # The client never holds the +rh_sk_+ key and never talks to Root Herald;
    # this backend helper is the only thing that does.
    #
    # @param enroll_request_blob [Hash] the opaque +EnrollBegin()+ blob from the
    #        client, relayed verbatim. Wire shape (camelCase keys): +ekPublicKey+,
    #        +akPublicArea+ (required), +platform+, +ekCertPem+,
    #        +ekCertificateChain+. String or symbol keys are accepted.
    # @return [RelayEnrollResult]
    # @raise [ArgumentError] if the blob lacks ekPublicKey/akPublicArea
    def relay_enroll(enroll_request_blob)
      ek = blob_field(enroll_request_blob, "ekPublicKey")
      ak = blob_field(enroll_request_blob, "akPublicArea")
      unless ek.is_a?(String) && ak.is_a?(String)
        raise ArgumentError,
              "relay_enroll requires an enroll request blob with ekPublicKey and akPublicArea"
      end

      status, body = raw_post("/api/v1/devices/enroll", enroll_request_blob)

      # 409 = already enrolled: the body carries only deviceId. Resolve it and
      # signal "skip activate" instead of treating it as an error.
      if status == 409
        data = parse_object(409, body)
        device_id = data["deviceId"]
        unless device_id.is_a?(String) && !device_id.empty?
          raise HttpError.new(409, body, "already-enrolled (409) response missing deviceId")
        end

        return RelayEnrollResult.new(already_enrolled: true, device_id: device_id, challenge: nil)
      end

      raise map_error(status, body) if status >= 400

      data = parse_object(status, body)
      device_id = data["deviceId"]
      credential_blob = data["credentialBlob"]
      encrypted_secret = data["encryptedSecret"]
      unless device_id.is_a?(String) && credential_blob.is_a?(String) && encrypted_secret.is_a?(String)
        raise HttpError.new(status, body, "enroll response missing deviceId/credentialBlob/encryptedSecret")
      end

      RelayEnrollResult.new(
        already_enrolled: false,
        device_id: device_id,
        challenge: EnrollChallenge.new(
          device_id: device_id,
          credential_blob: credential_blob,
          encrypted_secret: encrypted_secret
        )
      )
    end

    # Enroll relay — leg 2. POST /api/v1/devices/activate.
    #
    # Relays the client's +EnrollComplete()+ blob (the decrypted credential
    # secret) to Root Herald, completing the EK→AK credential-activation
    # handshake. Call this only when #relay_enroll returned
    # +already_enrolled == false+.
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

      data = post("/api/v1/devices/activate", activation_response)
      out_device_id = data["deviceId"]
      raise HttpError.new(200, data.to_json, "activate response missing deviceId") unless out_device_id.is_a?(String)

      ActivateResult.new(
        device_id: out_device_id,
        status: data["status"].is_a?(String) ? data["status"] : nil,
        enrolled_at: data["enrolledAt"].is_a?(String) ? data["enrolledAt"] : nil
      )
    end

    # POST /api/v1/attestations/challenge — mint a relay-friendly nonce. Relay
    # the nonce to the client; the client quotes over it, then submit the
    # resulting evidence with #verify using the returned challenge_id.
    #
    # @param device_hint [String, nil] optional advisory device hint
    # @return [Challenge]
    def issue_challenge(device_hint: nil)
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
    # @param policy [String, nil] tenant policy id/name or a "rootherald:builtin:*" name; unknown names fail closed (422)
    # @return [AttestResult]
    def verify(evidence, challenge_id:, policy: nil)
      raise ChallengeError.new(409, "", "verify requires challenge_id (from issue_challenge)") if challenge_id.to_s.empty?

      body = { "challengeId" => challenge_id, "evidence" => evidence }
      body["policy"] = policy unless policy.nil?

      data = post("/api/v1/attestations/verify", body)
      verdict_data = data["verdict"]
      raise HttpError.new(200, data.to_json, "verify response missing verdict") unless verdict_data.is_a?(Hash)

      AttestResult.new(
        verdict: Verdict.from_raw(verdict_data["verdict"]),
        verdict_data: verdict_data
      )
    end

    # @deprecated Renamed to #issue_challenge for the Client ABI 2.0 backend
    #   contract. Retained as a thin alias for backwards compatibility.
    def create_challenge(device_hint: nil)
      issue_challenge(device_hint: device_hint)
    end

    # @deprecated Renamed to #verify for the Client ABI 2.0 backend contract.
    #   Retained as a thin alias for backwards compatibility.
    def attest(evidence, challenge_id:, policy: nil)
      verify(evidence, challenge_id: challenge_id, policy: policy)
    end

    private

    # Authenticated JSON POST; maps non-2xx to a typed error and parses the body.
    def post(path, body)
      status, resp_body = raw_post(path, body)
      raise map_error(status, resp_body) if status >= 400

      parse_object(status, resp_body)
    end

    # Authenticated JSON POST returning +[status, body]+ verbatim, leaving status
    # interpretation to the caller (used by #relay_enroll, which must inspect the
    # enroll +409+). Mirrors @rootherald/node's +rawPost+.
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
