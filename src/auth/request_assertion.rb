# frozen_string_literal: true

require 'base64'
require 'digest'
require 'ed25519'
require 'json'
require 'jwt'
require 'jwt/eddsa'
require 'securerandom'
require 'uri'

module OAuthSlim
  class RequestAssertion
    VERSION = 1
    TYPE = 'authslim-request+jwt'
    MAX_TOKEN_BYTES = 8192
    AUDIENCE = /\A[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\z/

    class InvalidRequest < StandardError; end
    class InvalidIdentity < StandardError; end

    def self.from_env(env = ENV)
      enabled = env.fetch('AUTH_JWT_ENABLED', 'true')
      raise ArgumentError, 'AUTH_JWT_ENABLED must be true or false' unless %w[true false].include?(enabled)
      return unless enabled == 'true'
      return if env.fetch('AUTH_SCOPE', '').strip.empty?

      new(issuer: env.fetch('AUTH_SCOPE', ''), ttl: Integer(env.fetch('AUTH_JWT_TTL', '30')),
          rotation: Integer(env.fetch('AUTH_JWT_KEY_ROTATION_SECONDS', '3600')))
    end

    def self.request_metadata(env)
      query = env.fetch('QUERY_STRING', '')
      raise InvalidRequest, 'Invalid assertion controls' if query.bytesize > 2048

      controls = URI.decode_www_form(query).each_with_object({}) do |(name, value), result|
        unless %w[aud strip_prefix].include?(name) && !result.key?(name)
          raise InvalidRequest, 'Invalid assertion controls'
        end
        result[name] = value
      end
      audience = controls['aud']
      raise InvalidRequest, 'Invalid audience' unless audience.is_a?(String) && AUDIENCE.match?(audience)

      prefix = controls.fetch('strip_prefix', '')
      unless prefix.empty? || (prefix.bytesize <= 1024 && prefix.start_with?('/') && !prefix.match?(/[?#%\\\s[:cntrl:]]/))
        raise InvalidRequest, 'Invalid path prefix'
      end
      method = env['HTTP_X_FORWARDED_METHOD']
      target = env['HTTP_X_FORWARDED_URI']
      unless method.is_a?(String) && method.match?(/\A[A-Z]{1,32}\z/) &&
             target.is_a?(String) && target.bytesize <= 16_384 && target.start_with?('/') &&
             !target.match?(/[#\s[:cntrl:]]/)
        raise InvalidRequest, 'Invalid forwarded request'
      end

      path, separator, query_string = target.partition('?')
      unless prefix.empty? || path == prefix || path.start_with?("#{prefix}/")
        raise InvalidRequest, 'Path prefix does not match'
      end
      path = path.delete_prefix(prefix)
      path = '/' if path.empty?
      { audience:, method:, target: "#{path}#{separator}#{query_string}" }
    rescue ArgumentError
      raise InvalidRequest, 'Invalid assertion controls'
    end

    def initialize(issuer:, ttl: 30, rotation: 3600, clock: -> { Time.now.to_f },
                   monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
      unless issuer.is_a?(String) && issuer.bytesize.between?(1, 256) && issuer.valid_encoding? &&
             !issuer.match?(/[\s[:cntrl:]]/) && (!issuer.include?(':') || URI.parse(issuer).absolute?)
        raise ArgumentError, 'AUTH_SCOPE must be a nonempty StringOrURI'
      end
      raise ArgumentError, 'Assertion lifetime must be between 1 and 60 seconds' unless ttl.is_a?(Integer) && ttl.between?(1, 60)
      unless rotation.is_a?(Integer) && rotation.between?(ttl + 30, 86_400)
        raise ArgumentError, 'Invalid signing key rotation interval'
      end

      @issuer, @ttl, @rotation = issuer.freeze, ttl, rotation
      @clock, @monotonic = clock, monotonic
      @mutex = Mutex.new
      reset_keys
    rescue URI::InvalidURIError
      raise ArgumentError, 'AUTH_SCOPE must be a nonempty StringOrURI'
    end

    def issue(principal:, audience:, method:, target:)
      raise InvalidIdentity, 'Verified principal required' unless principal.is_a?(Hash)

      principal = principal.transform_keys(&:to_s)
      subject, role, parent_expiry = principal.values_at('sub', 'role', 'exp')
      unless subject.is_a?(String) && subject.bytesize.between?(1, 256) && !subject.strip.empty? &&
             role.is_a?(String) && role.bytesize <= 128 && parent_expiry.is_a?(Integer)
        raise InvalidIdentity, 'Invalid verified principal'
      end
      raise InvalidRequest, 'Invalid audience' unless audience.is_a?(String) && AUDIENCE.match?(audience)

      @mutex.synchronize do
        refresh_keys
        now = @clock.call.floor
        expiry = [now + @ttl, parent_expiry].min
        raise InvalidIdentity, 'Authentication expired' unless expiry > now

        claims = {
          ver: VERSION, iss: @issuer, aud: audience, sub: subject, role:,
          iat: now, exp: expiry, jti: SecureRandom.hex(16),
          request: { method:, target_sha256: Base64.urlsafe_encode64(Digest::SHA256.digest(target), padding: false) }
        }
        token = JWT.encode(claims, @signing_key, 'EdDSA', typ: TYPE, kid: @public_key.fetch(:kid))
        raise InvalidIdentity, 'Assertion too large' if token.bytesize > MAX_TOKEN_BYTES

        token
      end
    end

    def jwks
      @mutex.synchronize do
        refresh_keys
        { issuer: @issuer, keys: [@public_key, *@retired.map(&:first)] }
      end
    end

    private

    def reset_keys
      @pid = Process.pid
      @retired = []
      rotate_key
    end

    def refresh_keys
      reset_keys if @pid != Process.pid
      now = @monotonic.call
      @retired.reject! { |_, deadline| deadline <= now }
      return if now - @created_monotonic < @rotation

      @retired << [@public_key, now + @ttl + 30]
      rotate_key
    end

    def rotate_key
      @signing_key = Ed25519::SigningKey.generate
      @created_monotonic = @monotonic.call
      @public_key = {
        kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig',
        kid: SecureRandom.hex(16), created_at: @clock.call.floor,
        x: Base64.urlsafe_encode64(@signing_key.verify_key.to_bytes, padding: false)
      }.freeze
    end
  end
end
