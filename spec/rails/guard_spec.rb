# frozen_string_literal: true

require "spec_helper"

begin
  require "action_controller"
  require "action_controller/base"
  require "action_controller/test_case"
rescue LoadError
  RSpec.describe "Rails Guard" do
    it "is skipped because Rails is not installed" do
      skip "actionpack not installed"
    end
  end
  return
end

require "rootherald/rails/controller_concern"

# Configure the global Guard client once for the spec run.
RootHerald::Guard.client = RootHerald::Client.new(
  issuer: Fixtures::ISSUER,
  audience: Fixtures::AUDIENCE,
  jwks_fetcher: Fixtures.jwks_fetcher,
  http_transport: ->(*_args) { { status: 404, body: "" } }
)

class SignupsController < ActionController::Base
  include RootHerald::Guard
  guard_device :create, action: "signup"

  def create
    render json: { ok: true, device_id: rootherald_claims&.device_id }
  end
end

class StrictSignupsController < ActionController::Base
  include RootHerald::Guard
  guard_device :create, action: "wire", deny_on_warn: true

  def create
    head :ok
  end
end

RSpec.describe RootHerald::Guard do
  let(:controller) { SignupsController.new }
  let(:strict_controller) { StrictSignupsController.new }

  def dispatch(controller_class, headers: {})
    # Rack::MockRequest.env_for merges opts directly into the env — it has no
    # :headers special-casing — so hoist HTTP_* keys to the top level.
    env = Rack::MockRequest.env_for("/signups", { method: "POST" }.merge(headers))
    request = ActionDispatch::Request.new(env)
    response = ActionDispatch::Response.new
    controller_class.dispatch(:create, request, response)
    # Wrap in parens so the rescue modifier binds tightly to the JSON.parse
    # call only — without them, Ruby 3.3+ parses the whole array literal as
    # the rescue clause and fails with a syntax error.
    body = (JSON.parse(response.body) rescue response.body)
    [response.status, body]
  end

  it "returns 401 when no token is supplied" do
    status, body = dispatch(SignupsController)
    expect(status).to eq(401)
    expect(body["error"]).to eq("missing_attestation_token")
  end

  it "returns 200 with a valid token" do
    token = Fixtures.make_token
    status, body = dispatch(SignupsController, headers: { "HTTP_AUTHORIZATION" => "Bearer #{token}" })
    expect(status).to eq(200)
    expect(body["ok"]).to eq(true)
    expect(body["device_id"]).to eq("device-uuid-1234")
  end

  it "rejects expired tokens with 401" do
    token = Fixtures.make_token(iat: Time.now.to_i - 3600, exp_in: -600)
    status, body = dispatch(SignupsController, headers: { "HTTP_AUTHORIZATION" => "Bearer #{token}" })
    expect(status).to eq(401)
    expect(body["error"]).to eq("token_expired")
  end

  it "allows WARN by default" do
    token = Fixtures.make_token(ear_status: "warning")
    status, _ = dispatch(SignupsController, headers: { "HTTP_AUTHORIZATION" => "Bearer #{token}" })
    expect(status).to eq(200)
  end

  it "blocks WARN in strict mode" do
    token = Fixtures.make_token(ear_status: "warning")
    status, body = dispatch(StrictSignupsController, headers: { "HTTP_AUTHORIZATION" => "Bearer #{token}" })
    expect(status).to eq(403)
    expect(body["error"]).to eq("device_warned")
  end
end
