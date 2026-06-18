# frozen_string_literal: true

require "json"

module RootHerald
  # Top-level Root Herald client: REST API wrapper + token/webhook
  # verification facade.
  class Client
    DEFAULT_BASE_URL = "https://rootherald.io"
    DEFAULT_JWKS_URI = "https://rootherald.io/.well-known/jwks.json"

    attr_reader :issuer, :base_url, :jwks_fetcher, :token_verifier, :webhook_verifier

    # @param issuer [String] tenant URL, e.g. https://rootherald.io/myorg
    # @param api_key [String, nil]
    # @param base_url [String]
    # @param jwks_uri [String]
    # @param audience [String, nil] expected aud claim for token verification
    # @param timeout_seconds [Float]
    # @param jwks_fetcher [JwksFetcher, nil]
    # @param http_transport [#call, nil] callable taking
    #        +(method, url, headers, body)+ and returning
    #        +{status:, body:}+
    def initialize(issuer:, api_key: nil, base_url: DEFAULT_BASE_URL,
                   jwks_uri: DEFAULT_JWKS_URI, audience: nil,
                   timeout_seconds: 10.0, jwks_fetcher: nil, http_transport: nil)
      raise ArgumentError, "issuer is required" if issuer.nil? || issuer.empty?

      @issuer = issuer
      @api_key = api_key
      @base_url = base_url.to_s.chomp("/")
      @audience = audience
      @timeout = timeout_seconds
      @jwks_fetcher = jwks_fetcher || JwksFetcher.new(jwks_uri: jwks_uri, timeout_seconds: timeout_seconds)
      @token_verifier = Verifier.new(issuer: issuer, jwks: @jwks_fetcher, audience: audience)
      @webhook_verifier = WebhookVerifier.new(issuer: issuer, jwks: @jwks_fetcher)
      @http_transport = http_transport || build_default_transport
    end

    # @param token [String]
    # @return [AttestationClaims]
    def verify_token(token)
      @token_verifier.verify(token)
    end

    # @param signed_jwt [String]
    # @return [WebhookEvent]
    def verify_set(signed_jwt)
      @webhook_verifier.verify_set(signed_jwt)
    end

    # GET /api/v1/devices/{device_id}
    # @return [Hash]
    def get_device(device_id)
      request(:get, "/api/v1/devices/#{device_id}")
    end

    private

    def request(method, path, body: nil)
      url = "#{@base_url}#{path}"
      headers = { "Accept" => "application/json" }
      headers["Authorization"] = "Bearer #{@api_key}" if @api_key
      raw_body = nil
      if body
        headers["Content-Type"] = "application/json"
        raw_body = JSON.generate(body)
      end

      resp = @http_transport.call(method, url, headers, raw_body)
      status = resp[:status] || resp["status"]
      resp_body = resp[:body] || resp["body"] || ""

      raise HttpError.new(status, resp_body) if status >= 400
      return {} if status == 204 || resp_body.to_s.empty?

      begin
        decoded = JSON.parse(resp_body)
      rescue JSON::ParserError => e
        raise HttpError.new(status, resp_body, "non-JSON response: #{e.message}")
      end
      decoded.is_a?(Hash) ? decoded : { "value" => decoded }
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
