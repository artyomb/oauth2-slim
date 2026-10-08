# frozen_string_literal: true

require_relative '../spec_helper'
require_relative '../assertion_helpers'
require 'open3'
require 'tmpdir'

RSpec.describe OAuthSlim::AuthJwtMiddleware do
  include AssertionHelpers
  let(:clock) { AssertionTestClock.new }
  let(:signer) { make_signer }
  let(:calls) { [] }
  let(:fetches) { [] }
  let(:app) { ->(env) { calls << env; [200, {}, ['ok']] } }
  let(:fetch) { -> { fetches << true; JSON.generate(signer.jwks) } }
  let(:validator) { make_validator }

  def make_validator(**options)
    described_class.new(app, audience: 'insight', key_endpoint: 'http://auth:7000/.well-known/auth-jwks.json',
                        authorize: ->(identity, _) { identity['role'] == 'admin' },
                        clock: -> { clock.wall }, monotonic: -> { clock.mono }, fetch_jwks: fetch, **options)
  end

  before do
    validator
    clock.advance(10)
  end

  it 'accepts once, strips untrusted identity headers, and publishes only verified identity' do
    token = assertion
    env = request_env(token).merge('HTTP_X_TOKEN' => 'forged', 'HTTP_X_AUTHSLIM' => 'authorized', 'HTTP_X_ACCESS_TOKEN' => 'forged')
    expect(validator.call(env).first).to eq(200)
    expect(env['oauth_slim.identity']).to eq('iss' => 'auth.test', 'aud' => 'insight', 'sub' => 'alice', 'role' => 'admin')
    expect(env.keys).not_to include('HTTP_X_AUTH_JWT', 'HTTP_X_TOKEN', 'HTTP_X_AUTHSLIM', 'HTTP_X_ACCESS_TOKEN')
    expect(validator.call(request_env(token)).first).to eq(401)
    expect(calls.size).to eq(1)
  end

  it 'consumes a jti atomically under concurrent requests' do
    token = assertion
    results = 20.times.map { Thread.new { validator.call(request_env(token)).first } }.map(&:value)
    expect(results.count(200)).to eq(1)
    expect(results.count(401)).to eq(19)
    expect(fetches.size).to eq(1)
  end

  it 'retains consumption after application exceptions, failures, and websocket upgrades' do
    [500, 101, :raise].each do |outcome|
      backend = ->(_env) { raise 'application failed' if outcome == :raise; [outcome, {}, []] }
      guard = described_class.new(backend, audience: 'insight', key_endpoint: 'http://auth/keys',
                                  authorize: ->(*) { true }, clock: -> { clock.wall }, monotonic: -> { clock.mono }, fetch_jwks: fetch)
      clock.advance(10)
      token = assertion
      if outcome == :raise
        expect { guard.call(request_env(token)) }.to raise_error('application failed')
      else
        expect(guard.call(request_env(token)).first).to eq(outcome)
      end
      expect(guard.call(request_env(token)).first).to eq(401)
    end
  end

  it 'never evicts live replay entries and frees capacity only after expiry plus skew' do
    guard = make_validator(capacity: 1)
    clock.advance(10)
    token = assertion
    expect(guard.call(request_env(token)).first).to eq(200)
    expect(guard.call(request_env(assertion)).first).to eq(503)
    clock.advance(30)
    expect(guard.call(request_env(token)).first).to eq(401)
    expect(guard.call(request_env(assertion)).first).to eq(503)
    clock.advance(5)
    expect(guard.call(request_env(assertion)).first).to eq(200)
  end

  it 'rejects unauthorized requests without consuming replay capacity' do
    guard = make_validator(capacity: 1)
    clock.advance(10)
    expect(guard.call(request_env(assertion(role: 'viewer'))).first).to eq(403)
    expect(guard.call(request_env(assertion(audience: 'another-service'))).first).to eq(401)
    expect(guard.call(request_env(assertion)).first).to eq(200)
  end

  it 'rejects assertions for another service, method, path, or raw query regardless of forwarded headers' do
    [
      [assertion(audience: 'other'), {}],
      [assertion(method: 'POST'), {}],
      [assertion(target: '/private?a=2&a=1'), {}],
      [assertion(target: '/other'), {}],
      [assertion, { target: '/private?a=1&a=2&extra=x' }]
    ].each do |token, options|
      env = request_env(token, **options).merge('HTTP_X_FORWARDED_URI' => '/private?a=1&a=2')
      expect(validator.call(env).first).to eq(401)
    end
    expect(calls).to be_empty
  end

  it 'uses the trusted key endpoint issuer and enforces an optional issuer pin' do
    guard = make_validator(issuer: 'wrong-issuer')
    clock.advance(10)
    expect(guard.call(request_env(assertion)).first).to eq(503)
    other_signer = make_signer(issuer: 'other-realm')
    other = make_validator(fetch_jwks: -> { JSON.generate(other_signer.jwks) })
    clock.advance(10)
    expect(other.call(request_env(assertion(signer: other_signer))).first).to eq(200)
  end

  it 'checks startup boundaries even when the issuer clock is ahead' do
    guard = make_validator
    started = clock.wall
    clock.wall = started + 5
    old = assertion
    clock.wall = started
    expect(guard.call(request_env(old)).first).to eq(401)
    clock.advance(6)
    expect(guard.call(request_env(assertion)).first).to eq(200)
  end

  it 'rejects pre-restart assertions with an empty new replay cache' do
    old = assertion
    guard = make_validator
    clock.advance(10)
    expect(guard.call(request_env(old)).first).to eq(401)
    expect(guard.call(request_env(assertion)).first).to eq(200)
  end

  it 'does not resurrect expired assertions when wall time moves backwards' do
    token = assertion
    clock.advance(36)
    expect(validator.call(request_env(token)).first).to eq(401)
    clock.wall -= 30
    expect(validator.call(request_env(token)).first).to eq(401)
  end

  it 'requires explicit process initialization after fork' do
    allow(Process).to receive(:pid).and_return(Process.pid + 1)
    expect(validator.call(request_env(assertion)).first).to eq(503)
    validator.reset_process_state!
    clock.advance(10)
    expect(validator.call(request_env(assertion)).first).to eq(200)
  end

  it 'uses cached keys and never refreshes for a known-key signature failure' do
    good = assertion
    expect(validator.call(request_env(good)).first).to eq(200)
    header, payload, = good.split('.')
    corrupted = Base64.urlsafe_encode64("\0" * 64, padding: false)
    expect(validator.call(request_env([header, payload, corrupted].join('.'))).first).to eq(401)
    expect(validator.call(request_env(assertion)).first).to eq(200)
    expect(fetches.size).to eq(1)
  end

  it 'refreshes on rotation and removes retired keys on cache expiry' do
    rotating = make_signer(rotation: 60)
    guard = make_validator(fetch_jwks: -> { JSON.generate(rotating.jwks) })
    clock.advance(10)
    expect(guard.call(request_env(assertion(signer: rotating))).first).to eq(200)
    clock.advance(60)
    expect(guard.call(request_env(assertion(signer: rotating))).first).to eq(200)
    keys = described_class::KeyCache.new(fetch: -> { JSON.generate(rotating.jwks) }, monotonic: -> { clock.mono }, issuer: nil)
    old_kid = rotating.jwks[:keys].last[:kid]
    expect(keys.lookup(old_kid).first).to be_a(Ed25519::VerifyKey)
    clock.advance(61)
    expect { keys.lookup(old_kid) }.to raise_error(described_class::Invalid)
  end

  it 'bounds unknown-key refreshes and keeps still-valid cached keys during an outage' do
    expect(validator.call(request_env(assertion)).first).to eq(200)
    stranger = make_signer
    20.times { validator.call(request_env(assertion(signer: stranger))) }
    expect(fetches.size).to eq(1)
    clock.advance(6)
    allow(signer).to receive(:jwks).and_raise(described_class::Unavailable)
    expect(validator.call(request_env(assertion(signer: stranger))).first).to eq(503)
    expect(validator.call(request_env(assertion)).first).to eq(200)
    clock.advance(31)
    expect(validator.call(request_env(assertion)).first).to eq(503)
  end

  it 'rejects missing, malformed, oversized, wrong-type, and algorithm-confused tokens without fetching keys' do
    bad = [nil, '', 'not-a-token', 'x' * 8193]
    bad << JWT.encode({ sub: 'alice' }, nil, 'none', typ: described_class::TYPE, kid: 'a' * 32)
    bad << JWT.encode({ sub: 'alice' }, 'secret', 'HS256', typ: described_class::TYPE, kid: 'a' * 32)
    bad << JWT.encode({ sub: 'alice' }, 'secret', 'HS256', typ: 'JWT', jku: 'http://attacker/', kid: 'a' * 32)
    bad.each { |token| expect(validator.call(request_env(token)).first).to eq(401) }
    expect(fetches).to be_empty
  end

  it 'rejects malformed, duplicate, oversized, and private key sets' do
    good = JSON.parse(JSON.generate(signer.jwks))
    documents = [
      'not json', ' ' * 65_537, '{}',
      good.merge('issuer' => ''),
      good.merge('keys' => good['keys'] * 9),
      good.merge('keys' => good['keys'] * 2),
      good.merge('keys' => [good['keys'].first.merge('d' => 'private')]),
      good.merge('keys' => [good['keys'].first.merge('crv' => 'X25519')])
    ]
    documents.each do |document|
      raw = document.is_a?(String) ? document : JSON.generate(document)
      guard = make_validator(fetch_jwks: -> { raw })
      clock.advance(10)
      expect(guard.call(request_env(assertion)).first).to eq(503)
    end
  end

  it 'rejects signed but invalid issuer, claim types, lifetime, and request data' do
    key = Ed25519::SigningKey.generate
    kid = 'a' * 32
    jwks = { issuer: 'auth.test', keys: [{
      kty: 'OKP', crv: 'Ed25519', use: 'sig', alg: 'EdDSA', kid:,
      x: Base64.urlsafe_encode64(key.verify_key.to_bytes, padding: false)
    }] }
    guard = make_validator(fetch_jwks: -> { JSON.generate(jwks) })
    clock.advance(10)
    claims = signed_claims(assertion)
    invalid = [
      { 'iss' => 'wrong' }, { 'aud' => ['insight'] }, { 'ver' => 1.0 }, { 'ver' => 2 },
      { 'iat' => clock.wall.floor + 6 }, { 'iat' => '1800000000' },
      { 'exp' => claims['iat'] + 31 }, { 'exp' => claims['iat'] }, { 'exp' => nil },
      { 'sub' => '' }, { 'role' => ['admin'] }, { 'jti' => 'short' }, { 'nbf' => 0 },
      { 'request' => { 'method' => 'POST', 'target_sha256' => claims['request']['target_sha256'] } }
    ]
    invalid.each do |overrides|
      header = Base64.urlsafe_encode64(JSON.generate(alg: 'EdDSA', kid:, typ: described_class::TYPE), padding: false)
      payload = Base64.urlsafe_encode64(JSON.generate(claims.merge(overrides)), padding: false)
      message = "#{header}.#{payload}"
      token = "#{message}.#{Base64.urlsafe_encode64(key.sign(message), padding: false)}"
      expect(guard.call(request_env(token)).first).to eq(401), overrides.inspect
    end
    valid = JWT.encode(claims, key, 'EdDSA', kid:, typ: described_class::TYPE)
    expect(guard.call(request_env(valid)).first).to eq(200)
  end

  it 'rejects duplicate JSON members even when they carry a valid signature' do
    key = Ed25519::SigningKey.generate
    _, payload, = assertion.split('.')
    duplicate = Base64.urlsafe_encode64('{"alg":"EdDSA","alg":"EdDSA","kid":"' + ('a' * 32) + '","typ":"authslim-request+jwt"}', padding: false)
    message = "#{duplicate}.#{payload}"
    token = "#{message}.#{Base64.urlsafe_encode64(key.sign(message), padding: false)}"
    expect(validator.call(request_env(token)).first).to eq(401)
    expect(fetches).to be_empty
  end

  it 'loads in isolation without the producer, session signing key, Sinatra, or a database' do
    file = File.expand_path('../../examples/auth_jwt_middleware.rb', __dir__)
    code = "require #{file.inspect}; abort if defined?(SIGNING_KEY) || defined?(Sinatra) || defined?(DB); puts OAuthSlim::AuthJwtMiddleware::VERSION"
    out, error, status = Open3.capture3('bundle', 'exec', 'ruby', '-e', code)
    expect(status.success?).to be(true), error
    expect(out.strip).to eq('1')
  end
end
