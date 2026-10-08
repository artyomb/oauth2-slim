# frozen_string_literal: true

require_relative '../auth/request_assertion'
require_relative '../examples/auth_jwt_middleware'

class AssertionTestClock
  attr_accessor :wall, :mono

  def initialize
    @wall = 1_800_000_000.25
    @mono = 100.0
  end

  def advance(seconds)
    @wall += seconds
    @mono += seconds
  end
end

module AssertionHelpers
  def make_signer(**options)
    OAuthSlim::RequestAssertion.new(issuer: 'auth.test', clock: -> { clock.wall },
                                    monotonic: -> { clock.mono }, **options)
  end

  def assertion(signer: self.signer, audience: 'insight', method: 'GET', target: '/private?a=1&a=2', role: 'admin', **identity)
    principal = { sub: 'alice', role:, exp: clock.wall.floor + 300, **identity }
    signer.issue(principal:, audience:, method:, target:)
  end

  def request_env(token, method: 'GET', target: '/private?a=1&a=2')
    { 'HTTP_X_AUTH_JWT' => token, 'REQUEST_METHOD' => method, 'REQUEST_URI' => target }
  end

  def signed_claims(token)
    JWT.decode(token, nil, false).first
  end
end
