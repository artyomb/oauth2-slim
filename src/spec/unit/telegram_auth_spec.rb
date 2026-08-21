require_relative "../spec_helper"
require "base64"
require "logger"
require "rack/mock"
require "sinatra/base"
require "uri"

ENV["RACK_ENV"] = "test"
ENV["TELEGRAM_AUTH_BOT"] = "test_bot"
ENV["AUTH_DB_URL"] = "mock://"
ENV["AUTH_SCOPE"] = "app.test"
ENV["FORWARD_OAUTH_AUTH_URL"] = "/authorize"

LOGGER = Logger.new(File::NULL) unless defined?(LOGGER)

require_relative "../../auth/log_safety"
require_relative "../../auth/auth_forward"

class TelegramAuthSpecApp < Sinatra::Base
  set :environment, :test
  set :raise_errors, true
  set :show_exceptions, false
  set :sessions, { secret: "telegram-auth-spec-secret-" * 4 }
  set :views, File.expand_path("../../views", __dir__)

  helpers AuthForward
end

RSpec.describe TelegramAuth do
  let(:request) { Rack::MockRequest.new(TelegramAuthSpecApp) }

  around do |example|
    revoked = FORWARD_AUTH[:revoked?]
    issuer = ENV['OIDC_ISSUER']
    ENV['OIDC_ISSUER'] = 'https://auth.test/oauth_slim'
    example.run
  ensure
    FORWARD_AUTH[:revoked?] = revoked
    issuer.nil? ? ENV.delete('OIDC_ISSUER') : ENV['OIDC_ISSUER'] = issuer
  end

  before do
    AUTH_CODES.clear
    TelegramAuth::AUTH_DB.fetch = []
  end

  after { AUTH_CODES.clear }

  it "starts authorization through the Telegram authorization endpoint" do
    response = request.get(
      "/auth",
      "HTTP_HOST" => "auth.test",
      "HTTP_X_FORWARDED_PROTO" => "https",
      "HTTP_X_FORWARDED_HOST" => "app.test",
      "HTTP_X_FORWARDED_URI" => "/private?page=2"
    )

    expect(response.status).to eq(302)
    location = URI.parse(response["location"])
    query = URI.decode_www_form(location.query).to_h
    expect(location.path).to eq("/authorize")
    expect(query).to include(
      "redirect_uri" => "https://app.test/private",
      "response_type" => "code",
      "state" => Base64.urlsafe_encode64("page=2")
    )
  end

  it "keeps confirmation pending while no linked account exists" do
    response = request.get("/auth_confirm")

    expect(response.status).to eq(404)
    expect(AUTH_CODES).to be_empty
    expect(auth_cookie?(response)).to be(false)

    TelegramAuth::AUTH_DB.fetch = [{ id: 42, login: "alice" }]
    confirmed = request.get("/auth_confirm")

    expect(confirmed.status).to eq(200)
    expect(AUTH_CODES).to be_empty
    expect(auth_cookie?(confirmed)).to be(false)
  end

  it "issues and consumes an OAuth code for a linked Telegram account" do
    TelegramAuth::AUTH_DB.fetch = [{
      id: 42,
      login: "alice",
      name: "Alice",
      role: "admin",
      org: "example",
      email: "alice@example.test",
      auth_code: "telegram-correlation",
      password_hash: "must-not-leak"
    }]
    original_query = "page=2&filter=active"
    state = Base64.urlsafe_encode64(original_query)
    redirect_uri = "https://app.test/private?existing=kept#details"
    nonce = "telegram-oidc-nonce"
    client_id = "telegram-client"
    requested_scope = "openid email"

    authorize = request.get(
      "/authorize?#{URI.encode_www_form(redirect_uri:, state:, nonce:, client_id:, scope: requested_scope, response_type: 'code')}",
      "HTTP_HOST" => "auth.test"
    )

    expect(authorize.status).to eq(302)
    location = URI.parse(authorize["location"])
    callback_query = URI.decode_www_form(location.query).to_h
    authorization_code = callback_query.fetch("code")
    expect(location.to_s).to start_with("https://app.test/private?")
    expect(location.fragment).to eq("details")
    expect(callback_query).to include("existing" => "kept", "state" => state)

    issued = AUTH_CODES.fetch(authorization_code)
    expect(issued).to include(
      scope: "app.test",
      requested_scope:,
      client_id:,
      redirect_uri:,
      nonce:,
      uid: 42,
      login: "alice",
      name: "Alice",
      role: "admin",
      org: "example",
      email: "alice@example.test"
    )
    expect(issued[:time]).to be_within(2).of(Time.now.to_i)
    expect(issued.keys).to contain_exactly(
      :scope, :requested_scope, :client_id, :redirect_uri, :nonce, :time,
      :uid, :login, :name, :role, :org, :email
    )
    forwarded_callback_uri = location.request_uri

    callback = request.get(
      "/auth",
      "HTTP_HOST" => "auth.test",
      "HTTP_X_FORWARDED_PROTO" => "https",
      "HTTP_X_FORWARDED_HOST" => "app.test",
      "HTTP_X_FORWARDED_URI" => forwarded_callback_uri
    )

    expect(callback.status).to eq(302)
    expect(callback["location"]).to eq("https://app.test/private?#{original_query}")
    expect(auth_cookie?(callback)).to be(true)
    expect(AUTH_CODES).not_to have_key(authorization_code)
    token_payload = JWT.decode(auth_cookie_value(callback), SIGNING_KEY.verify_key, true, algorithm: "EdDSA").first
    expect(token_payload).to include(
      "uid" => 42,
      "login" => "alice",
      "role" => "admin",
      "email" => "alice@example.test"
    )

    replay = request.get(
      "/auth",
      "HTTP_HOST" => "auth.test",
      "HTTP_X_FORWARDED_PROTO" => "https",
      "HTTP_X_FORWARDED_HOST" => "app.test",
      "HTTP_X_FORWARDED_URI" => forwarded_callback_uri
    )
    expect(replay.status).to eq(404)
  end

  describe "GET /auth/optional" do
    it "allows an anonymous request without identity headers or an auth cookie" do
      response = optional_auth_request(
        headers: {
          "HTTP_X_AUTHSLIM" => "authorized",
          "HTTP_X_TOKEN" => { login: "forged", role: "admin" }.to_json
        }
      )

      expect(response.status).to eq(200)
      expect(response["location"]).to be_nil
      expect(response["X-AuthSlim"]).to be_nil
      expect(response["X-Token"]).to be_nil
      expect(auth_cookie?(response)).to be(false)
    end

    it "forwards server-owned identity headers for a valid token" do
      token = signed_token(login: "alice", role: "editor")
      response = optional_auth_request(
        token:,
        headers: { "HTTP_X_TOKEN" => { login: "forged", role: "admin" }.to_json }
      )

      expect(response.status).to eq(200)
      expect(response["X-AuthSlim"]).to eq("authorized")
      expect(JSON.parse(response["X-Token"])).to include("login" => "alice", "role" => "editor")
    end

    it "treats invalid and expired tokens as anonymous" do
      ["not-a-jwt", signed_token(exp: Time.now.to_i - 1)].each do |token|
        response = optional_auth_request(token:)

        expect(response.status).to eq(200)
        expect(response["X-AuthSlim"]).to be_nil
        expect(response["X-Token"]).to be_nil
      end
    end

    it "treats a revoked token as anonymous" do
      FORWARD_AUTH[:revoked?] = -> { true }
      response = optional_auth_request(token: signed_token)

      expect(response.status).to eq(200)
      expect(response["X-AuthSlim"]).to be_nil
      expect(response["X-Token"]).to be_nil
    end

    it "completes an authorization callback before accepting an existing token" do
      code = "optional-auth-code"
      AUTH_CODES[code] = {
        scope: "app.test",
        time: Time.now.to_i,
        uid: 84,
        login: "bob",
        role: "admin",
        email: "bob@example.test"
      }
      state = Base64.urlsafe_encode64("page=2")
      forwarded_uri = "/news?#{URI.encode_www_form(code:, state:)}"

      response = optional_auth_request(token: signed_token(login: "alice"), forwarded_uri:)

      expect(response.status).to eq(302)
      expect(response["location"]).to eq("https://app.test/news?page=2")
      expect(AUTH_CODES).not_to have_key(code)
      token_payload = JWT.decode(auth_cookie_value(response), SIGNING_KEY.verify_key, true, algorithm: "EdDSA").first
      expect(token_payload).to include("uid" => 84, "login" => "bob", "role" => "admin")
    end

    it "rejects an unknown authorization code instead of allowing anonymous access" do
      response = optional_auth_request(forwarded_uri: "/news?code=missing")

      expect(response.status).to eq(404)
      expect(response.body).to eq("AUTH code not found")
    end
  end

  describe "GET /auth/ceph" do
    it "intercepts Dashboard logout and clears the local authentication" do
      response = ceph_auth_request(
        token: signed_token,
        forwarded_uri: "/auth/oauth2/logout?return=/",
        headers: { "HTTP_X_FORWARDED_HOST" => "ceph.test" }
      )

      expect(response.status).to eq(302)
      expect(response["location"]).to eq("https://ceph.test")
      expect(response["X-Access-Token"]).to be_nil
      expect(auth_cookie_value(response)).to eq("")
    end

    it "exposes only the authenticated raw token as X-Access-Token" do
      token = signed_token(login: "alice", role: "admin")
      response = ceph_auth_request(
        token:,
        headers: { "HTTP_X_ACCESS_TOKEN" => signed_token(login: "forged", role: "admin") }
      )

      expect(response.status).to eq(200)
      expect(response["X-AuthSlim"]).to eq("authorized")
      expect(response["X-Access-Token"]).to eq(token)
      expect(JSON.parse(response["X-Token"])).to include("login" => "alice", "role" => "admin")
    end

    it "does not expose the raw token through generic forward auth" do
      token = signed_token
      response = forward_auth_request("/auth", token:, headers: { "HTTP_X_ACCESS_TOKEN" => "forged" })

      expect(response.status).to eq(200)
      expect(response["X-AuthSlim"]).to eq("authorized")
      expect(response["X-Access-Token"]).to be_nil
    end

    it "does not expose a client header for invalid, expired, or revoked authentication" do
      invalid_tokens = ["not-a-jwt", signed_token(exp: Time.now.to_i - 1)]
      invalid_tokens.each do |token|
        response = ceph_auth_request(token:, headers: { "HTTP_X_ACCESS_TOKEN" => "forged" })

        expect(response.status).to eq(302)
        expect(response["X-Access-Token"]).to be_nil
      end

      FORWARD_AUTH[:revoked?] = -> { true }
      revoked = ceph_auth_request(
        token: signed_token,
        headers: { "HTTP_X_ACCESS_TOKEN" => "forged" }
      )
      expect(revoked.status).to eq(302)
      expect(revoked["X-Access-Token"]).to be_nil
    end

    it "renews an otherwise valid legacy token that lacks Ceph claims" do
      legacy_token = JWT.encode(
        { login: "alice", role: "admin", exp: Time.now.to_i + 3600, iat: Time.now.to_i },
        SIGNING_KEY,
        "EdDSA"
      )
      response = ceph_auth_request(token: legacy_token)

      expect(response.status).to eq(302)
      expect(response["X-Access-Token"]).to be_nil
      expect(URI.parse(response["location"]).path).to eq("/authorize")
    end

    it "issues a compatible token after completing the authorization callback" do
      code = "ceph-auth-code"
      AUTH_CODES[code] = {
        scope: "app.test",
        time: Time.now.to_i,
        uid: 84,
        login: "bob",
        name: "Bob",
        role: "admin",
        email: "bob@example.test"
      }

      callback = ceph_auth_request(forwarded_uri: "/?code=#{code}")
      expect(callback.status).to eq(302)
      token = auth_cookie_value(callback)

      authenticated = ceph_auth_request(token:)
      claims = JWT.decode(
        authenticated["X-Access-Token"], SIGNING_KEY.verify_key, true, algorithm: "EdDSA"
      ).first
      expect(claims).to include(
        "sub" => "84",
        "name" => "Bob",
        "email" => "bob@example.test",
        "role" => "admin",
        "roles" => ["admin"]
      )
      expect(claims.fetch("jti")).to match(/\A[0-9a-f-]{36}\z/)
    end
  end

  describe "GET /oauth2/sign_out" do
    it "clears authentication and follows the configured issuer logout URL" do
      logout_url = "#{ENV.fetch('OIDC_ISSUER')}/logout"
      response = request.get(
        "/oauth2/sign_out?#{URI.encode_www_form(rd: logout_url)}",
        "HTTP_COOKIE" => "#{COOKIE_TOKEN_NAME}=#{signed_token}",
        "HTTP_X_FORWARDED_PROTO" => "https",
        "HTTP_X_FORWARDED_HOST" => "ceph.test"
      )

      expect(response.status).to eq(302)
      expect(response["location"]).to eq(logout_url)
      expect(auth_cookie_value(response)).to eq("")
    end

    it "ignores an untrusted post-logout redirect" do
      response = request.get(
        "/oauth2/sign_out?#{URI.encode_www_form(rd: 'https://attacker.test/')}",
        "HTTP_X_FORWARDED_PROTO" => "https",
        "HTTP_X_FORWARDED_HOST" => "ceph.test"
      )

      expect(response.status).to eq(302)
      expect(response["location"]).to eq("https://ceph.test")
    end
  end

  it "rejects a linked account without a login" do
    TelegramAuth::AUTH_DB.fetch = [{ id: 42 }]

    response = request.get(
      "/authorize?#{URI.encode_www_form(redirect_uri: "https://app.test/private")}",
      "HTTP_HOST" => "auth.test"
    )

    expect(response.status).to eq(401)
    expect(AUTH_CODES).to be_empty
  end

  def auth_cookie?(response)
    !auth_cookie_value(response).nil?
  end

  def optional_auth_request(token: nil, forwarded_uri: "/news", headers: {})
    forward_auth_request("/auth/optional", token:, forwarded_uri:, headers:)
  end

  def ceph_auth_request(token: nil, forwarded_uri: "/", headers: {})
    forward_auth_request("/auth/ceph", token:, forwarded_uri:, headers:)
  end

  def forward_auth_request(path, token: nil, forwarded_uri: "/news", headers: {})
    env = {
      "HTTP_HOST" => "auth.test",
      "HTTP_X_FORWARDED_PROTO" => "https",
      "HTTP_X_FORWARDED_HOST" => "app.test",
      "HTTP_X_FORWARDED_URI" => forwarded_uri,
      **headers
    }
    env["HTTP_COOKIE"] = "#{COOKIE_TOKEN_NAME}=#{token}" if token
    request.get(path, env)
  end

  def signed_token(login: "alice", role: "viewer", exp: Time.now.to_i + 3600)
    JWT.encode(
      {
        sub: login,
        login:,
        name: login,
        email: "#{login}@example.test",
        role:,
        roles: role.to_s.empty? ? [] : [role.to_s],
        jti: SecureRandom.uuid,
        exp:,
        iat: Time.now.to_i
      },
      SIGNING_KEY,
      "EdDSA"
    )
  end

  def auth_cookie_value(response)
    cookie = Array(response["set-cookie"]).find { |value| value.start_with?("#{COOKIE_TOKEN_NAME}=") }
    Rack::Utils.unescape(cookie&.split(";", 2)&.first&.split("=", 2)&.last.to_s) unless cookie.nil?
  end
end
