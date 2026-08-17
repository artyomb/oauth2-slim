# frozen_string_literal: true

require_relative '../spec_helper'
require 'base64'
require 'ed25519'
require 'logger'
require 'rack/mock'
require 'sinatra/base'
require 'uri'
require 'zlib'

ENV['RACK_ENV'] = 'test'
ENV['AUTH_SCOPE'] = 'app.test'
ENV['FORWARD_OAUTH_AUTH_URL'] = '/authorize'

SIGNATURE_AUTH_SPEC_SIGNING_KEY = Ed25519::SigningKey.generate
ENV['AUTH_VERIFY_KEY'] = SIGNATURE_AUTH_SPEC_SIGNING_KEY.verify_key.to_bytes.unpack1('H*')

LOGGER = Logger.new(File::NULL) unless defined?(LOGGER)

require_relative '../../auth/authorization_code'
require_relative '../../auth/signature_auth'
require_relative '../../auth/token'

class SignatureAuthSpecApp < Sinatra::Base
  set :environment, :test
  set :raise_errors, true
  set :show_exceptions, false
  set :sessions, { secret: 'signature-auth-spec-secret-' * 4 }
  set :views, File.expand_path('../../views', __dir__)

  helpers Token, AuthorizationCode, SignatureAuth

  helpers do
    def valid_redirect_uri!(value) = URI.parse(value)
  end
end

ENV.delete('AUTH_VERIFY_KEY')

RSpec.describe SignatureAuth do
  let(:request) { Rack::MockRequest.new(SignatureAuthSpecApp) }

  before { AUTH_CODES.clear }
  after { AUTH_CODES.clear }

  it 'accepts a legacy signature without a role' do
    response = authorize(signature: signed_payload('alice'), redirect: 'do')

    expect(response.status).to eq(302)
    grant = authorization_grant(response)
    expect(grant).to include(login: 'alice')
    expect(grant).not_to have_key(:role)
  end

  it 'accepts a role-bearing signature and preserves the role in the SSO flow' do
    signature = signed_payload('alice', role: 'editor')
    login = authorize(signature:)

    expect(login.status).to eq(200)
    token = auth_cookie_value(login)
    expect(decoded_token(token)).to include('login' => 'alice', 'role' => 'editor')

    callback = authorize(signature:, redirect: 'do', token:)
    expect(callback.status).to eq(302)
    expect(authorization_grant(callback)).to include(login: 'alice', role: 'editor')
  end

  it 'rejects a role changed after signing' do
    message = signed_message('alice', role: 'user')
    signature = SIGNATURE_AUTH_SPEC_SIGNING_KEY.sign(message).unpack1('H*')
    tampered_payload = encode_payload("#{message.sub(/\|user\z/, '|admin')}|#{signature}")

    response = authorize(signature: tampered_payload, redirect: 'do')

    expect(response.status).to eq(200)
    expect(response.body).to include('Invalid authorization')
    expect(AUTH_CODES).to be_empty
  end

  def authorize(signature:, redirect: nil, token: nil)
    query = {
      redirect_uri: 'https://app.test/callback', response_type: 'code',
      scope: 'openid', signature:, redirect:
    }.compact
    env = {}
    env['HTTP_COOKIE'] = "#{COOKIE_TOKEN_NAME}=#{token}" if token
    request.get("/authorize?#{URI.encode_www_form(query)}", env)
  end

  def signed_payload(login, role: nil)
    message = signed_message(login, role:)
    signature = SIGNATURE_AUTH_SPEC_SIGNING_KEY.sign(message).unpack1('H*')
    encode_payload("#{message}|#{signature}")
  end

  def signed_message(login, role: nil)
    ['app.test', Time.now.to_i, login, role].compact.join('|')
  end

  def encode_payload(value)
    Base64.urlsafe_encode64(Zlib::Deflate.deflate(value))
  end

  def authorization_grant(response)
    code = URI.decode_www_form(URI.parse(response['location']).query).to_h.fetch('code')
    AUTH_CODES.fetch(code)
  end

  def auth_cookie_value(response)
    cookie = Array(response['set-cookie']).find { |value| value.start_with?("#{COOKIE_TOKEN_NAME}=") }
    Rack::Utils.unescape(cookie.split(';', 2).first.split('=', 2).last)
  end

  def decoded_token(token)
    JWT.decode(token, SIGNING_KEY.verify_key, true, algorithm: 'EdDSA').first
  end
end
