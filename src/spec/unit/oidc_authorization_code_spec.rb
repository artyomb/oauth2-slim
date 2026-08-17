# frozen_string_literal: true

require_relative '../spec_helper'
require 'json'
require 'logger'
require 'rack/mock'
require 'sinatra/base'
require 'uri'

ENV['RACK_ENV'] = 'test'
ENV['FORWARD_OAUTH_AUTH_URL'] = '/authorize'
ENV['OIDC_CLIENT_SECRET'] = 'oidc-spec-secret-' * 4
ENV['OIDC_ISSUER'] = 'https://auth.test'

LOGGER = Logger.new(File::NULL) unless defined?(LOGGER)

require_relative '../../auth/auth20'
require_relative '../../auth/token'

class OIDCAuthorizationCodeSpecApp < Sinatra::Base
  set :environment, :test
  set :raise_errors, true
  set :show_exceptions, false

  helpers Token, AuthorizationCode, Auth20

  get '/issue' do
    code = create_authorization_code(
      auth_scope: 'app.test',
      context: authorization_request_context,
      identity: {
        uid: 42,
        login: 'alice',
        email: 'alice@example.test',
        ignored: 'not-in-the-grant'
      }
    )

    content_type :json
    JSON.generate(code:)
  end
end

RSpec.describe AuthorizationCode do
  let(:request) { Rack::MockRequest.new(OIDCAuthorizationCodeSpecApp) }

  before { AUTH_CODES.clear }
  after { AUTH_CODES.clear }

  it 'binds an OIDC nonce to the authorization code and ID token' do
    nonce = 'random-client-nonce'
    client_id = 'mayan-edms'
    requested_scope = 'openid email'
    redirect_uri = 'https://mayan.example.test/oidc/callback/'
    code = issue_code(nonce:, client_id:, requested_scope:, redirect_uri:)

    expect(AUTH_CODES.fetch(code)).to include(
      scope: 'app.test',
      requested_scope:,
      client_id:,
      redirect_uri:,
      nonce:,
      uid: 42,
      login: 'alice',
      email: 'alice@example.test'
    )
    expect(AUTH_CODES.fetch(code)).not_to have_key(:ignored)

    response = exchange_code(code, client_id:)
    expect(response.status).to eq(200)
    token_response = JSON.parse(response.body)
    expect(token_response['scope']).to eq(requested_scope)

    access_claims = JWT.decode(
      token_response.fetch('access_token'), SIGNING_KEY.verify_key, true,
      algorithm: 'EdDSA'
    ).first
    expect(access_claims).to include('role' => '')

    userinfo = request.get(
      '/oauth_slim/user',
      'HTTP_AUTHORIZATION' => "Bearer #{token_response.fetch('access_token')}"
    )
    expect(userinfo.status).to eq(200)
    expect(JSON.parse(userinfo.body)).to include('role' => '')

    claims = JWT.decode(
      token_response.fetch('id_token'), ENV.fetch('OIDC_CLIENT_SECRET'), true,
      algorithm: 'HS256'
    ).first
    expect(claims).to include(
      'iss' => 'https://auth.test',
      'sub' => '42',
      'aud' => client_id,
      'nonce' => nonce,
      'email' => 'alice@example.test'
    )
    expect(AUTH_CODES).not_to have_key(code)
    expect(exchange_code(code, client_id:).status).to eq(404)
  end

  it 'keeps generic OAuth token responses free of ID tokens' do
    code = issue_code(requested_scope: 'profile email')
    response = exchange_code(code, client_id: 'generic-client')

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).not_to have_key('id_token')
  end

  it 'rejects expired authorization codes when they are consumed' do
    code = issue_code
    AUTH_CODES.fetch(code)[:time] = Time.now.to_i - AuthorizationCode::AUTH_CODE_TTL - 1

    expect(exchange_code(code, client_id: 'expired-client').status).to eq(404)
    expect(AUTH_CODES).not_to have_key(code)
  end

  def issue_code(
    nonce: nil, client_id: 'test-client', requested_scope: 'openid',
    redirect_uri: 'https://app.test/callback'
  )
    query = URI.encode_www_form(
      client_id:, redirect_uri:, response_type: 'code',
      scope: requested_scope, state: 'client-state', nonce:
    )
    response = request.get("/issue?#{query}")
    JSON.parse(response.body).fetch('code')
  end

  def exchange_code(code, client_id:)
    request.post(
      '/oauth_slim/token',
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
      input: URI.encode_www_form(
        code:, client_id:, client_secret: ENV.fetch('OIDC_CLIENT_SECRET'),
        grant_type: 'authorization_code'
      )
    )
  end
end
