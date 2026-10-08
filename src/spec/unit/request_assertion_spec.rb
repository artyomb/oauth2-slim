# frozen_string_literal: true

require_relative '../spec_helper'
require_relative '../assertion_helpers'

RSpec.describe OAuthSlim::RequestAssertion do
  include AssertionHelpers
  let(:clock) { AssertionTestClock.new }
  let(:signer) { make_signer }

  it 'signs a bounded request assertion using a public-only JWKS' do
    token = assertion
    jwks = JSON.parse(JSON.generate(signer.jwks))
    public_key = Ed25519::VerifyKey.new(Base64.urlsafe_decode64(jwks['keys'].first['x']))
    claims, header = JWT.decode(token, public_key, true, algorithm: 'EdDSA', verify_expiration: false)

    expect(header).to include('alg' => 'EdDSA', 'typ' => described_class::TYPE, 'kid' => jwks['keys'].first['kid'])
    expect(claims).to include('ver' => 1, 'iss' => 'auth.test', 'aud' => 'insight', 'sub' => 'alice', 'role' => 'admin')
    expect(claims['exp'] - claims['iat']).to eq(30)
    expect(claims['jti']).to match(/\A[0-9a-f]{32}\z/)
    expect(claims['request']).to eq('method' => 'GET', 'target_sha256' => Base64.urlsafe_encode64(Digest::SHA256.digest('/private?a=1&a=2'), padding: false))
    expect(jwks).to include('issuer' => 'auth.test')
    expect(jwks['keys'].first.keys).to contain_exactly('kty', 'crv', 'alg', 'use', 'kid', 'created_at', 'x')
  end

  it 'accepts new service audiences without configuration and uses fresh assertion IDs' do
    tokens = %w[insight new-service new-service].map { |audience| signed_claims(assertion(audience:)) }
    expect(tokens.map { |claims| claims['aud'] }).to eq(%w[insight new-service new-service])
    expect(tokens.map { |claims| claims['jti'] }.uniq.size).to eq(3)
  end

  it 'caps the assertion at the parent session expiry and rejects expired authentication' do
    expect(signed_claims(assertion(exp: clock.wall.floor + 2))['exp']).to eq(clock.wall.floor + 2)
    expect { assertion(exp: clock.wall.floor) }.to raise_error(described_class::InvalidIdentity)
    expect { signer.issue(principal: 'authorized', audience: 'insight', method: 'GET', target: '/') }.to raise_error(described_class::InvalidIdentity)
  end

  it 'rotates in memory, retains public overlap, and retires keys by monotonic time' do
    rotating = make_signer(rotation: 60)
    first = JWT.decode(assertion(signer: rotating), nil, false).last['kid']
    clock.advance(60)
    second = JWT.decode(assertion(signer: rotating), nil, false).last['kid']
    expect(first).not_to eq(second)
    expect(rotating.jwks[:keys].map { |key| key[:kid] }).to include(first, second)
    clock.wall -= 1000
    clock.mono += 61
    expect(rotating.jwks[:keys].map { |key| key[:kid] }).not_to include(first)
    expect(make_signer.jwks[:keys].first[:kid]).not_to eq(second)
  end

  it 'enables assertions by default only with a configured realm and supports explicit disablement' do
    expect(described_class.from_env({})).to be_nil
    expect(described_class.from_env('AUTH_SCOPE' => 'auth.test')).to be_a(described_class)
    expect(described_class.from_env('AUTH_JWT_ENABLED' => 'true')).to be_nil
    expect(described_class.from_env('AUTH_JWT_ENABLED' => 'false', 'AUTH_SCOPE' => 'auth.test')).to be_nil
  end

  it 'rejects invalid explicit global configuration' do
    [
      { 'AUTH_JWT_ENABLED' => 'yes' },
      { 'AUTH_JWT_ENABLED' => 'true', 'AUTH_SCOPE' => 'auth.test', 'AUTH_JWT_TTL' => '61' },
      { 'AUTH_JWT_ENABLED' => 'true', 'AUTH_SCOPE' => 'auth.test', 'AUTH_JWT_KEY_ROTATION_SECONDS' => '1' }
    ].each { |env| expect { described_class.from_env(env) }.to raise_error(ArgumentError) }
  end

  describe '.request_metadata' do
    def metadata(query, target = '/insight/x%2Fy?a=1&a=2&aud=forged', **headers)
      described_class.request_metadata({
        'QUERY_STRING' => query, 'HTTP_X_FORWARDED_METHOD' => 'POST',
        'HTTP_X_FORWARDED_URI' => target, 'HTTP_X_AUDIENCE' => 'forged', **headers
      })
    end

    it 'uses auth-address controls and preserves escaped paths and raw query parameters' do
      expect(metadata('aud=stack-insight_stack_insight&strip_prefix=%2Finsight')).to eq(
        audience: 'stack-insight_stack_insight', method: 'POST', target: '/x%2Fy?a=1&a=2&aud=forged'
      )
      expect(metadata('aud=insight&strip_prefix=%2Finsight', '/insight?')[:target]).to eq('/?')
      expect(metadata('aud=insight', '/x%2fy?a=+&a=%20')[:target]).to eq('/x%2fy?a=+&a=%20')
    end

    it 'rejects missing, duplicate, nested, malformed, and unbounded controls' do
      ['', 'aud=', 'aud[]=insight', 'aud=a&aud=b', 'aud=a%0Ab', "aud=#{'a' * 129}",
       'aud=ok&strip_prefix=/x&strip_prefix=/x', 'aud=ok&strip_prefix=/x?y', 'aud=ok&unknown=x'].each do |query|
        expect { metadata(query) }.to raise_error(described_class::InvalidRequest)
      end
    end

    it 'rejects prefix confusion and missing or malformed request metadata' do
      expect { metadata('aud=insight&strip_prefix=/insight', '/insights') }.to raise_error(described_class::InvalidRequest)
      expect { metadata('aud=insight', '/private', 'HTTP_X_FORWARDED_METHOD' => nil) }.to raise_error(described_class::InvalidRequest)
      expect { metadata('aud=insight', 'https://attacker.test/') }.to raise_error(described_class::InvalidRequest)
    end
  end
end
