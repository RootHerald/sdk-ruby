# frozen_string_literal: true

require "json"
require "openssl"
require "monitor"
require "jwt"

module RootHerald
  # Fetches and caches the JWKS document from the issuer.
  #
  # Thread-safe — uses a +Monitor+ so concurrent token verifications
  # share one JWKS refresh. A +cooldown_seconds+ window prevents JWKS
  # refresh storms when tokens reference unknown kids.
  class JwksFetcher
    DEFAULT_CACHE_TTL = 3600.0
    DEFAULT_COOLDOWN = 30.0

    attr_reader :jwks_uri

    # @param jwks_uri [String]
    # @param http_fetcher [Proc] callable taking a URL, returning the body
    #        string. Defaults to a Faraday-based fetcher.
    # @param cache_ttl_seconds [Float]
    # @param cooldown_seconds [Float]
    # @param timeout_seconds [Float]
    def initialize(jwks_uri:, http_fetcher: nil, cache_ttl_seconds: DEFAULT_CACHE_TTL,
                   cooldown_seconds: DEFAULT_COOLDOWN, timeout_seconds: 5.0)
      raise ArgumentError, "jwks_uri is required" if jwks_uri.nil? || jwks_uri.empty?

      @jwks_uri = jwks_uri
      @http_fetcher = http_fetcher || build_default_fetcher(timeout_seconds)
      @cache_ttl = cache_ttl_seconds
      @cooldown = cooldown_seconds
      @mon = Monitor.new
      @cache = nil           # Hash[kid => OpenSSL::PKey]
      @fetched_at = 0.0
      @last_refresh_attempt = 0.0
    end

    # @param kid [String]
    # @return [OpenSSL::PKey::PKey] public key matching +kid+
    # @raise [JwksError] when the kid cannot be resolved
    def get_key(kid)
      @mon.synchronize do
        now = monotime
        cache = @cache
        stale = cache.nil? || (now - @fetched_at) > @cache_ttl
        missing_kid = !cache.nil? && !cache.key?(kid)
        in_cooldown = (now - @last_refresh_attempt) < @cooldown

        if stale || (missing_kid && !in_cooldown)
          @last_refresh_attempt = now
          refresh
          cache = @cache
        end

        raise JwksError, "No JWKS key found for kid=#{kid.inspect}" if cache.nil? || !cache.key?(kid)

        cache[kid]
      end
    end

    # @return [Hash{String => OpenSSL::PKey::PKey}]
    def keys
      @mon.synchronize do
        if @cache.nil? || (monotime - @fetched_at) > @cache_ttl
          refresh
        end
        @cache.dup
      end
    end

    private

    def refresh
      body = begin
        @http_fetcher.call(@jwks_uri)
      rescue JwksError
        raise
      rescue StandardError => e
        raise JwksError, "Failed to fetch JWKS: #{e.message}"
      end

      doc = begin
        JSON.parse(body)
      rescue JSON::ParserError => e
        raise JwksError, "JWKS body is not JSON: #{e.message}"
      end

      raise JwksError, "JWKS document missing 'keys' array" unless doc.is_a?(Hash) && doc["keys"].is_a?(Array)

      parsed = {}
      doc["keys"].each do |jwk|
        kid = jwk["kid"]
        next if kid.nil? || kid.empty?

        begin
          parsed[kid] = JWT::JWK.import(jwk).public_key
        rescue StandardError => e
          raise JwksError, "Failed to parse JWK kid=#{kid.inspect}: #{e.message}"
        end
      end

      raise JwksError, "JWKS document contained no usable keys" if parsed.empty?

      @cache = parsed
      @fetched_at = monotime
    end

    def build_default_fetcher(timeout_seconds)
      require "faraday"
      conn = Faraday.new do |f|
        f.options.timeout = timeout_seconds
        f.options.open_timeout = timeout_seconds
      end
      lambda do |url|
        resp = conn.get(url) { |req| req.headers["Accept"] = "application/json" }
        raise JwksError, "JWKS fetch returned HTTP #{resp.status}" if resp.status >= 400

        resp.body.to_s
      end
    end

    def monotime
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
