# frozen_string_literal: true

require "ipaddr"
require "json"
require "time"
require "uri"

module RootHerald
  # Server -> server Background-Check client.
  #
  # The customer's keyless client collects opaque blobs (no keys, no Root Herald
  # contact) and hands them to the customer's own server. The server uses this
  # client, authenticated with its +rh_sk_+ secret key, to drive three
  # ceremonies of two legs each, the same six helpers as @rootherald/node:
  #
  #   enroll      #relay_enroll / #relay_activate         POST /api/v1/attest/enroll, /activate
  #   mint a key  #issue_key_challenge / #certify_key     POST /api/v1/keys/challenge, /certify
  #   attest      #issue_challenge / #verify              POST /api/v1/attest/challenge, /verify
  #
  # Nothing a client sends locates a row. The server resolves the tenant from
  # the +rh_sk_+ key, the challenge from the nonce the proof was made over, the
  # enrollment from the +enrollmentId+ it minted, and the installation from the
  # proof itself. No identifier the server assigns is relayed to a device.
  #
  # The verdict is computed by Root Herald and returned to the backend — it never
  # travels through the keyless client.
  class Client
    DEFAULT_BASE_URL = "https://rootherald.io"
    SECRET_KEY_PREFIX = "rh_sk_"
    # Per-request timeout in seconds, the same in every Root Herald server SDK.
    DEFAULT_TIMEOUT_SECONDS = 30.0
    # Marks a 429 as the metered budget, whatever the body says.
    QUOTA_HEADER = "x-rootherald-quota"

    # Ask: prove which enrolled installation this is.
    ASK_IDENTITY = "identity"
    # Ask: prove the boot / configuration state (quote + event log).
    ASK_POSTURE = "posture"

    # Key purpose: a signing key (ES256 / RS256).
    KEY_PURPOSE_SIGN = "sign"
    # Key purpose: a decryption key (ECDH-ES / RSA-OAEP-256). The server refuses
    # it before wire 8.1.
    KEY_PURPOSE_DECRYPT = "decrypt"
    KEY_PURPOSES = [KEY_PURPOSE_SIGN, KEY_PURPOSE_DECRYPT].freeze
    KEY_FORMATS = %w[jwe apple-ecies].freeze
    EC_ALGS = %w[ES256 ECDH-ES].freeze
    RSA_ALGS = %w[RS256 RSA-OAEP-256].freeze

    # A challenge minted by #issue_challenge. Relay +challenge+ to the client
    # verbatim; it carries the nonce and the ask the server bound to it. Keep
    # +nonce+ — the backend's handle for the challenge, the same bytes as the
    # second segment of +challenge+ — and pass it to #verify.
    Challenge = Struct.new(:nonce, :challenge, :expires_at, keyword_init: true)

    # A key challenge minted by #issue_key_challenge. Relay +key_challenge+ to
    # the client's +MintKey+ verbatim; keep +nonce+ and pass it to #certify_key.
    KeyChallenge = Struct.new(:nonce, :key_challenge, :expires_at, keyword_init: true)

    # The key #certify_key registered. +device_id+ is the tenant's alias for the
    # device that holds it; +key_id+ is stable across rotations of the same
    # purpose; +alg+ is "ES256" / "RS256" for a sign key, "ECDH-ES" /
    # "RSA-OAEP-256" for a decrypt key; +format+ ("jwe" | "apple-ecies") is
    # present for a decrypt key only; +jwk+ is the public half as a Hash,
    # +{ "kty" => "EC", "crv" => "P-256", "x", "y" }+ or
    # +{ "kty" => "RSA", "n", "e" }+, chosen by the device; +hardware_bound+ is
    # false on macOS, where only possession is proved; +certified_at+ is a Time.
    # Verify later device signatures with +RootHerald::KeySignatures.verify+.
    CertifiedKey = Struct.new(:device_id, :key_id, :purpose, :alg, :format, :jwk, :hardware_bound, :certified_at,
                              keyword_init: true)

    # The activation challenge — the +201+ response body of
    # POST /api/v1/attest/enroll, handed to the client's +EnrollComplete+ leg.
    # A TPM device gets +credential_blob+ / +encrypted_secret+ (the
    # TPM2_MakeCredential outputs it feeds into TPM2_ActivateCredential); a
    # macOS device gets +challenge_nonce+ to sign. +enrollment_id+ names the
    # open enrollment and comes back in the activation blob.
    EnrollChallenge = Struct.new(:enrollment_id, :credential_blob, :encrypted_secret, :challenge_nonce,
                                 keyword_init: true) do
      # @return [Hash] the +201+ body in wire shape (camelCase keys, absent
      #   fields omitted), ready to relay to the client's +EnrollComplete+
      def to_wire
        {
          "enrollmentId" => enrollment_id,
          "credentialBlob" => credential_blob,
          "encryptedSecret" => encrypted_secret,
          "challengeNonce" => challenge_nonce
        }.compact
      end
    end

    # Result of the enroll-relay leg (#relay_enroll), mirroring
    # @rootherald/node's +RelayEnrollResult+.
    #
    # Every enrollment issues a challenge, a device already known included:
    # each activation creates a new installation of the device with its own
    # attestation key, which the client keeps as a blob. Relay +challenge+ to
    # the client's +EnrollComplete+, then call #relay_activate.
    #
    # +challenge+ is nil for an iOS enrollment: its +201+ body is empty and
    # nothing goes back to the device. The backend learns its alias for the
    # device from #relay_activate (TPM, macOS) or from the first verdict (iOS).
    RelayEnrollResult = Struct.new(:challenge, keyword_init: true)

    # The terminal response of the activate-relay leg (#relay_activate) —
    # POST /api/v1/attest/activate. +device_id+ is the load-bearing field the
    # backend maps to its user. It is this tenant's alias for the device, not a
    # global identifier, and must not be relayed to the device. It does not
    # change across installations, re-enrollments or a TPM clear.
    ActivateResult = Struct.new(:device_id, :status, :enrolled_at, keyword_init: true)

    # The result of #verify: the device verdict and the full verdict data.
    #
    # +assurance_claims_met+ / +enrollment_required+ mirror @rootherald/node:
    # the top-level +assuranceClaimsMet+ (satisfied assurance URNs) and
    # +enrollment_required+ (the attest-first / enroll-on-miss signal).
    #
    # The cohort accessors expose the ADDITIVE, advisory-only cohort fields the
    # server populates on +verdict_data["device"]+ (camelCase keys) when a
    # quote-bound event log was supplied — never a trust gate. They return nil
    # (or {} for the per-PCR map) when the server omitted them.
    AttestResult = Struct.new(:verdict, :verdict_data, :assurance_claims_met, :enrollment_required,
                              keyword_init: true) do
      # @return [Hash] the raw +device+ sub-object, passed through verbatim
      def device
        d = verdict_data.is_a?(Hash) ? verdict_data["device"] : nil
        d.is_a?(Hash) ? d : {}
      end

      # @return [String, nil] the tenant's alias for the device
      #   (+verdict.device.ueid+); nil below the pseudonymous disclosure class
      def device_id
        v = device["ueid"]
        v.is_a?(String) ? v : nil
      end

      # @return [Hash] the binding the server enforced, +{ "key" => keyId,
      #   "devices" => [alias, ...] }+ with absent members omitted; {} when the
      #   challenge named none
      def expected
        v = verdict_data.is_a?(Hash) ? verdict_data["expected"] : nil
        v.is_a?(Hash) ? v : {}
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
    # @param timeout_seconds [Float] per-request timeout; default DEFAULT_TIMEOUT_SECONDS
    # @param http_transport [#call, nil] callable taking
    #        +(method, url, headers, body)+ and returning
    #        +{status:, body:, headers:}+; +headers+ is optional, a Hash of
    #        response header name (lowercased) to value
    # @raise [ArgumentError] if the key is empty, is not an rh_sk_ key, or the
    #   base URL is not https (loopback excepted)
    def initialize(secret_key:, base_url: DEFAULT_BASE_URL,
                   timeout_seconds: DEFAULT_TIMEOUT_SECONDS, http_transport: nil)
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
    # Admission runs under the identity policy bound to the API key; a device
    # that could never satisfy it is refused before it gets an AK
    # (AdmissionRefusedError, 422 admission_refused).
    #
    # @param enroll_request_blob [Hash] the opaque +EnrollBegin()+ blob from the
    #        client, relayed verbatim, unknown fields included. Wire shape
    #        (camelCase keys), discriminated by +platform+: a TPM blob
    #        ("windows" | "linux") carries +ekPublicKey+ and +attestationKey+
    #        +{ publicArea, parentPublicArea, qualifiedName }+; a macOS blob
    #        carries +ekPublicKey+ and +akPublicArea+; an iOS blob carries
    #        +iosKeyId+, +iosAttestationObject+ and +nonce+. String or symbol
    #        keys are accepted.
    # @return [RelayEnrollResult]
    # @raise [ArgumentError] if the blob is not one of the three shapes. A flat
    #   TPM blob (+akPublicArea+ under "windows" / "linux") is the 7.0 shape
    #   and is refused here, before any request.
    def relay_enroll(enroll_request_blob)
      unless well_formed_enroll_blob?(enroll_request_blob)
        raise ArgumentError, "relay_enroll requires an enroll request blob: ekPublicKey with " \
                             "attestationKey { publicArea, parentPublicArea, qualifiedName } (windows/linux), " \
                             "ekPublicKey with akPublicArea (macos), or iosKeyId, iosAttestationObject and nonce (ios)"
      end
      ios = enroll_platform(enroll_request_blob) == "ios"

      status, body, headers = raw_post("/api/v1/attest/enroll", enroll_request_blob)
      raise map_error(status, body, headers) if status >= 400

      data = parse_object(status, body)
      return RelayEnrollResult.new(challenge: nil) if ios && !data.key?("enrollmentId")

      challenge = EnrollChallenge.new(
        enrollment_id: data["enrollmentId"],
        credential_blob: data["credentialBlob"],
        encrypted_secret: data["encryptedSecret"],
        challenge_nonce: data["challengeNonce"]
      )
      tpm = challenge.credential_blob.is_a?(String) && challenge.encrypted_secret.is_a?(String)
      macos = challenge.challenge_nonce.is_a?(String)
      unless challenge.enrollment_id.is_a?(String) && (tpm || macos)
        raise HttpError.new(status, body,
                            "enroll response missing enrollmentId with credentialBlob/encryptedSecret or challengeNonce")
      end

      RelayEnrollResult.new(challenge: challenge)
    end

    # Enroll relay — leg 2. POST /api/v1/attest/activate.
    #
    # Relays the client's +EnrollComplete()+ blob to Root Herald, completing
    # the activation handshake for the enrollment #relay_enroll opened.
    #
    # @param activation_response [Hash] the opaque +EnrollComplete()+ blob,
    #        relayed verbatim. Wire shape (camelCase keys): +enrollmentId+ plus
    #        +decryptedSecret+ (TPM) or +signature+ (macOS). String or symbol
    #        keys are accepted.
    # @return [ActivateResult] +device_id+ is the load-bearing field
    # @raise [ArgumentError] if the blob lacks enrollmentId or a proof
    def relay_activate(activation_response)
      enrollment_id = blob_field(activation_response, "enrollmentId")
      proof = %w[decryptedSecret signature].any? { |k| blob_field(activation_response, k).is_a?(String) }
      unless enrollment_id.is_a?(String) && !enrollment_id.empty? && proof
        raise ArgumentError,
              "relay_activate requires an activation response with enrollmentId and decryptedSecret or signature"
      end

      data = post("/api/v1/attest/activate", activation_response)
      device_id = data["deviceId"]
      raise HttpError.new(200, data.to_json, "activate response missing deviceId") unless device_id.is_a?(String)

      ActivateResult.new(
        device_id: device_id,
        status: data["status"].is_a?(String) ? data["status"] : nil,
        enrolled_at: data["enrolledAt"].is_a?(String) ? data["enrolledAt"] : nil
      )
    end

    # POST /api/v1/keys/challenge — mint a single-use key challenge for a
    # purpose. Relay +key_challenge.key_challenge+ to the client verbatim; its
    # +MintKey+ answers with a certification, which you submit with
    # #certify_key using the returned nonce.
    #
    # Refused with 422 key_disclosure_too_low when the API key's disclosure
    # ceiling is below pseudonymous: a key whose id could never be returned is
    # never minted.
    #
    # @param purpose [String] KEY_PURPOSE_SIGN or KEY_PURPOSE_DECRYPT
    # @param expected_devices [Array<String>, nil] aliases you enrolled; the
    #        certify leg is refused unless one of them certified the key. Pass
    #        the alias of the device that just passed an attest challenge, so
    #        the key provably comes from it.
    # @return [KeyChallenge]
    # @raise [ArgumentError] if the purpose is not one of KEY_PURPOSES, or
    #   expected_devices is not a non-empty list of non-empty strings
    def issue_key_challenge(purpose:, expected_devices: nil)
      unless KEY_PURPOSES.include?(purpose)
        raise ArgumentError, "issue_key_challenge requires purpose: to be one of #{KEY_PURPOSES.join('/')}"
      end

      body = { "purpose" => purpose }
      body["expectedDevices"] = require_alias_list(expected_devices, "expected_devices") unless expected_devices.nil?

      data = post("/api/v1/keys/challenge", body)
      unless %w[nonce keyChallenge expiresAt].all? { |k| data[k].is_a?(String) }
        raise HttpError.new(200, data.to_json, "key challenge response missing nonce/keyChallenge/expiresAt")
      end

      KeyChallenge.new(
        nonce: data["nonce"],
        key_challenge: data["keyChallenge"],
        expires_at: data["expiresAt"]
      )
    end

    # POST /api/v1/keys/certify — relay the client's +MintKey+ output under the
    # key challenge's nonce and return the key Root Herald registered. Store
    # +key_id+ and +jwk+ against +device_id+; later signatures are checked
    # locally with +RootHerald::KeySignatures.verify+.
    #
    # The certification is relayed verbatim, whichever platform shape it is:
    # +{ publicArea, attest, signature }+ from a TPM, or the +platform+-tagged
    # body from macOS / iOS. The key is the call's only output, so a malformed
    # one is refused with HttpError rather than returned half-parsed.
    #
    # @param certification [Hash] the opaque +MintKey()+ blob; string or
    #        symbol keys are accepted
    # @param nonce [String] the single-use handle from #issue_key_challenge
    # @return [CertifiedKey]
    # @raise [ArgumentError] if the nonce is empty or the certification is not
    #   one of the shapes above; no request is made
    def certify_key(certification, nonce:)
      raise ArgumentError, "certify_key requires nonce (from issue_key_challenge)" if nonce.to_s.empty?
      unless well_formed_certification?(certification)
        raise ArgumentError, "certify_key requires the client's certification: { publicArea, attest, signature } " \
                             "on a TPM, or the platform form from macOS / iOS"
      end

      data = post("/api/v1/keys/certify", { "nonce" => nonce, "certification" => certification })
      parse_certified_key(data)
    end

    # POST /api/v1/attest/challenge — mint a challenge that carries the ask.
    # Relay +challenge.challenge+ to the client verbatim; it quotes over it,
    # then submit the resulting evidence with #verify using the returned nonce.
    #
    # What the device must prove is fixed here, not at verify time. Policies
    # bind to the API key (an identity policy and, on Pro, a posture policy);
    # the server resolves the policy from the key that mints the challenge and
    # pins it on the challenge. A +policy+ field in a hand-built body is
    # refused with 400 policy_bound_to_key.
    #
    # @param ask [Array<String>, nil] any of ASK_IDENTITY / ASK_POSTURE; nil or
    #        empty means the server default, identity + posture. An ask the
    #        server does not know is 400 invalid_ask (InvalidAskError).
    # @param expected_key [String, nil] the key_id of a key you certified. Only
    #        the installation holding that key can pass; any other answers a
    #        failing verdict with reason expected_device_mismatch. An unknown
    #        id is 422 expected_unknown.
    # @param expected_devices [Array<String>, nil] aliases you enrolled. Only
    #        one of them can pass; any other device answers a failing verdict
    #        with reason expected_device_mismatch. An unknown alias is
    #        422 expected_unknown.
    # @return [Challenge]
    # @raise [ArgumentError] if expected_key is not a non-empty string or
    #   expected_devices is not a non-empty list of non-empty strings
    def issue_challenge(ask: nil, expected_key: nil, expected_devices: nil)
      body = {}
      body["ask"] = Array(ask).map(&:to_s) unless ask.nil? || Array(ask).empty?
      body["expectedKey"] = require_non_empty_string(expected_key, "expected_key") unless expected_key.nil?
      body["expectedDevices"] = require_alias_list(expected_devices, "expected_devices") unless expected_devices.nil?
      data = post("/api/v1/attest/challenge", body)
      unless %w[nonce challenge expiresAt].all? { |k| data[k].is_a?(String) }
        raise HttpError.new(200, data.to_json, "challenge response missing nonce/challenge/expiresAt")
      end

      Challenge.new(
        nonce: data["nonce"],
        challenge: data["challenge"],
        expires_at: data["expiresAt"]
      )
    end

    # POST /api/v1/attest/verify — submit the opaque evidence blob for
    # server-side appraisal and return the verdict.
    #
    # An un-enrolled / failing device is NOT an error — it returns a normal
    # AttestResult carrying +:fail+/+:warn+. Only protocol/auth/budget problems
    # raise; a response whose verdict token is not one of pass/warn/fail is
    # one too (HttpError).
    #
    # The verdict is computed by Root Herald and returned here, to the customer's
    # backend — it never travels through the keyless client.
    #
    # The appraisal runs under the policy pinned on the challenge at mint,
    # which the server resolved from the API key; nothing here can name a
    # different one. A +policy+ field in a hand-built body is refused with
    # 400 policy_bound_to_key.
    #
    # When the challenge named +expected_key+ or +expected_devices+, pass the
    # same values here: the verdict must echo them under +expected+, and a
    # response that does not is refused with ExpectedNotEnforcedError.
    #
    # @param evidence [Hash, Array, String] opaque blob from the client collector; passed through verbatim
    # @param nonce [String] the single-use handle from #issue_challenge
    # @param requested_disclosure_class [String, nil] optional disclosure ceiling
    #        ("verdict" | "pseudonymous" | "derived" | "full"); omitted from the
    #        request body when nil
    # @param expected_key [String, nil] the expected_key the challenge was issued with
    # @param expected_devices [Array<String>, nil] the expected_devices the
    #        challenge was issued with
    # @return [AttestResult]
    # @raise [ArgumentError] if the nonce is empty; no request is made
    # @raise [ExpectedNotEnforcedError] if the verdict does not echo the binding
    def verify(evidence, nonce:, requested_disclosure_class: nil, expected_key: nil, expected_devices: nil)
      raise ArgumentError, "verify requires nonce (from issue_challenge)" if nonce.to_s.empty?

      expected_key = require_non_empty_string(expected_key, "expected_key") unless expected_key.nil?
      expected_devices = require_alias_list(expected_devices, "expected_devices") unless expected_devices.nil?

      body = { "nonce" => nonce, "evidence" => evidence }
      body["requestedDisclosureClass"] = requested_disclosure_class unless requested_disclosure_class.nil?

      data = post("/api/v1/attest/verify", body)
      verdict_data = data["verdict"]
      raise HttpError.new(200, data.to_json, "verify response missing verdict") unless verdict_data.is_a?(Hash)

      device = verdict_data["device"].is_a?(Hash) ? verdict_data["device"] : {}
      verdict = Verdict.from_raw(device["verdict"])
      if verdict.nil?
        raise HttpError.new(200, data.to_json,
                            "verify response verdict.device.verdict is not pass/warn/fail (got #{device['verdict'].inspect})")
      end

      result = AttestResult.new(
        verdict: verdict,
        verdict_data: verdict_data,
        assurance_claims_met: data["assuranceClaimsMet"].is_a?(Array) ? data["assuranceClaimsMet"] : [],
        enrollment_required: data["enrollmentRequired"] == true
      )
      require_expected_enforced(result, data, expected_key, expected_devices) if expected_key || expected_devices
      result
    end

    private

    # A verdict is only as bound as the server says it enforced. The API
    # ignores unknown JSON fields, so a server that predates the binding would
    # accept any device and answer a verdict with no +expected+ block;
    # comparing the echo with what was asked turns that silence into a refusal.
    def require_expected_enforced(result, data, expected_key, expected_devices)
      echoed = result.expected
      refuse = lambda do |what|
        raise ExpectedNotEnforcedError.new(200, data.to_json,
                                           "verify response did not echo the #{what} the challenge named; " \
                                           "the binding was not enforced")
      end
      refuse.call("expected_key") if expected_key && echoed["key"] != expected_key
      return unless expected_devices

      # Aliases are GUIDs: the server accepts any spelling and echoes lowercase.
      asked = expected_devices.map { |a| normalize_alias(a) }.uniq.sort
      devices = echoed["devices"]
      refuse.call("expected_devices") unless devices.is_a?(Array) && devices.grep(String).map { |a| normalize_alias(a) }.uniq.sort == asked
      ueid = result.device_id
      refuse.call("expected_devices") if result.verdict != Verdict::FAIL && ueid && !asked.include?(normalize_alias(ueid))
    end

    def normalize_alias(alias_value)
      alias_value.strip.downcase
    end

    def require_non_empty_string(value, field)
      raise ArgumentError, "#{field} must be a non-empty string" unless value.is_a?(String) && !value.empty?

      value
    end

    def require_alias_list(value, field)
      unless value.is_a?(Array) && !value.empty? && value.all? { |v| v.is_a?(String) && !v.empty? }
        raise ArgumentError, "#{field} must be a non-empty list of non-empty strings"
      end

      value
    end

    # The 8.0 TPM body nests the AK; macOS stays flat (the enclave key has no
    # parent); iOS is its own shape. A flat TPM body is the 7.0 shape: the
    # server would answer wire_version_unsupported, and refusing it here keeps
    # the message specific.
    def well_formed_enroll_blob?(blob)
      return false unless blob.is_a?(Hash)

      case enroll_platform(blob)
      when "ios"
        %w[iosKeyId iosAttestationObject nonce].all? { |k| blob_field(blob, k).is_a?(String) }
      when "macos"
        blob_field(blob, "ekPublicKey").is_a?(String) && blob_field(blob, "akPublicArea").is_a?(String) &&
          !blob_key?(blob, "attestationKey")
      when "windows", "linux"
        ak = blob_field(blob, "attestationKey")
        blob_field(blob, "ekPublicKey").is_a?(String) && ak.is_a?(Hash) &&
          %w[publicArea parentPublicArea qualifiedName].all? { |k| blob_field(ak, k).is_a?(String) } &&
          !blob_key?(blob, "akPublicArea")
      else
        false
      end
    end

    # The discriminator as JSON.generate will send it: a symbol-keyed Ruby
    # blob may spell it as a Symbol.
    def enroll_platform(blob)
      platform = blob_field(blob, "platform")
      platform.is_a?(Symbol) ? platform.to_s : platform
    end

    # The certification is per platform and relayed verbatim, so only its
    # outer shape is checked: a TPM certification's three base64 strings, or a
    # platform-tagged body from macOS or iOS.
    def well_formed_certification?(value)
      return false unless value.is_a?(Hash)
      return true if blob_field(value, "platform").is_a?(String)

      %w[publicArea attest signature].all? { |k| blob_field(value, k).is_a?(String) }
    end

    # Read a /keys/certify response. The JWK family must match +alg+: an EC
    # key signs ES256 or agrees ECDH-ES, an RSA key signs RS256 or wraps
    # RSA-OAEP-256. Anything else is refused rather than surfaced half-parsed.
    def parse_certified_key(data)
      refuse = ->(why) { raise HttpError.new(200, data.to_json, "certify response #{why}") }
      refuse.call("missing deviceId") unless data["deviceId"].is_a?(String) && !data["deviceId"].empty?
      refuse.call("missing keyId") unless data["keyId"].is_a?(String) && !data["keyId"].empty?
      refuse.call("purpose is not one of #{KEY_PURPOSES.join('/')}") unless KEY_PURPOSES.include?(data["purpose"])
      refuse.call("missing hardwareBound") unless [true, false].include?(data["hardwareBound"])
      jwk = read_jwk(data["jwk"])
      refuse.call("jwk is not an EC P-256 or RSA public key") unless jwk
      algs = jwk["kty"] == "EC" ? EC_ALGS : RSA_ALGS
      refuse.call("alg #{data['alg'].inspect} does not fit a #{jwk['kty']} key") unless algs.include?(data["alg"])
      format = data["format"]
      refuse.call("format is not one of #{KEY_FORMATS.join('/')}") unless format.nil? || KEY_FORMATS.include?(format)

      certified_at = begin
        Time.iso8601(data["certifiedAt"].to_s)
      rescue ArgumentError
        refuse.call("certifiedAt is not a timestamp")
      end

      CertifiedKey.new(
        device_id: data["deviceId"],
        key_id: data["keyId"],
        purpose: data["purpose"],
        alg: data["alg"],
        format: format,
        jwk: jwk,
        hardware_bound: data["hardwareBound"],
        certified_at: certified_at
      )
    end

    def read_jwk(value)
      return nil unless value.is_a?(Hash)

      if value["kty"] == "EC" && value["crv"] == "P-256" && value["x"].is_a?(String) && value["y"].is_a?(String)
        value.slice("kty", "crv", "x", "y")
      elsif value["kty"] == "RSA" && value["n"].is_a?(String) && value["e"].is_a?(String)
        value.slice("kty", "n", "e")
      end
    end

    # Authenticated JSON POST; maps non-2xx to a typed error and parses the body.
    def post(path, body)
      status, resp_body, resp_headers = raw_post(path, body)
      raise map_error(status, resp_body, resp_headers) if status >= 400

      parse_object(status, resp_body)
    end

    # Authenticated JSON POST returning +[status, body, headers]+ verbatim
    # (header names lowercased), leaving status interpretation to the caller.
    def raw_post(path, body)
      url = "#{@base_url}#{path}"
      headers = {
        "Authorization" => "Bearer #{@secret_key}",
        "Content-Type" => "application/json",
        "Accept" => "application/json"
      }
      resp = @http_transport.call(:post, url, headers, JSON.generate(body))
      resp_headers = resp[:headers] || resp["headers"]
      resp_headers = resp_headers.is_a?(Hash) ? resp_headers.to_h { |k, v| [k.to_s.downcase, v.to_s] } : {}
      [resp[:status] || resp["status"], (resp[:body] || resp["body"] || "").to_s, resp_headers]
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

    def blob_key?(blob, key)
      blob.key?(key) || blob.key?(key.to_sym)
    end

    # Map a non-2xx response to the matching typed error, mirroring
    # @rootherald/node. Where one status carries two refusals the server's
    # +error+ code (or a header) tells them apart; a code no class covers
    # stays a plain HttpError with +server_error+ preserved.
    def map_error(status, body, headers = {})
      message = nil
      code = nil
      retry_after = nil
      budget = nil
      begin
        parsed = JSON.parse(body)
        if parsed.is_a?(Hash)
          message = %w[message detail error_description].map { |f| parsed[f] }.find { |v| v.is_a?(String) }
          code = [parsed["error"], parsed["code"]].find { |v| v.is_a?(String) }
          retry_after = parsed["retryAfterSeconds"] if parsed["retryAfterSeconds"].is_a?(Integer)
          budget = read_budget(parsed["budget"])
        end
      rescue JSON::ParserError
        # non-JSON body; fall through to status-based message
      end
      header_retry = headers["retry-after"].to_s.strip
      retry_after = Integer(header_retry, 10) if header_retry.match?(/\A\d+\z/)

      case status
      when 401
        (code == "activation_refused" ? ActivationRefusedError : InvalidSecretKeyError).new(status, body, message, code)
      when 422
        klass = case code
                when "admission_refused" then AdmissionRefusedError
                when "unknown_policy", nil then UnknownPolicyError
                else HttpError
                end
        klass.new(status, body, message, code)
      when 409
        (code == "key_rotation_conflict" ? HttpError : ChallengeError).new(status, body, message, code)
      when 400
        (%w[invalid_ask invalid_purpose].include?(code) ? InvalidAskError : InvalidEvidenceError).new(status, body, message, code)
      when 429
        if code == "budget_exhausted" || headers.key?(QUOTA_HEADER)
          QuotaExceededError.new(status, body, message, code, budget)
        else
          RateLimitedError.new(status, body, message, code, retry_after)
        end
      else HttpError.new(status, body, message, code)
      end
    end

    def read_budget(value)
      return nil unless value.is_a?(Hash) && value["id"].is_a?(String) && value["name"].is_a?(String)

      Budget.new(id: value["id"], name: value["name"])
    end

    def build_default_transport
      require "faraday"
      conn = Faraday.new do |f|
        f.options.timeout = @timeout
      end
      lambda do |method, url, headers, body|
        resp = conn.run_request(method, url, body, headers)
        { status: resp.status, body: resp.body.to_s, headers: resp.headers.to_h }
      end
    end
  end
end
