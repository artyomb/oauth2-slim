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

    authorize = request.get(
      "/authorize?#{URI.encode_www_form(redirect_uri:, state:)}",
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
      uid: 42,
      login: "alice",
      name: "Alice",
      role: "admin",
      org: "example",
      email: "alice@example.test"
    )
    expect(issued[:time]).to be_within(2).of(Time.now.to_i)
    expect(issued.keys).to contain_exactly(:scope, :time, :uid, :login, :name, :role, :org, :email)
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

  def auth_cookie_value(response)
    cookie = Array(response["set-cookie"]).find { |value| value.start_with?("#{COOKIE_TOKEN_NAME}=") }
    Rack::Utils.unescape(cookie&.split(";", 2)&.first&.split("=", 2)&.last.to_s) unless cookie.nil?
  end
end
