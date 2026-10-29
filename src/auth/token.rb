require 'ed25519'
require 'jwt'
require 'jwt/eddsa'
require 'securerandom'
require_relative 'log_safety'

KEY_FILENAME = ENV['RACK_ENV'] == 'production' ? '/private_keys/signing_key' : "#{__dir__}/../signing_key"
system 'mkdir -p /private_keys' if ENV['RACK_ENV'] == 'production'

COOKIE_TOKEN_NAME = ENV.fetch('COOKIE_TOKEN_NAME', 'auth_token')

if File.exist?(KEY_FILENAME)
  signature_key_hex = IO.read(KEY_FILENAME)
  SIGNING_KEY = Ed25519::SigningKey.new([signature_key_hex].pack('H*'))
else
  SIGNING_KEY = Ed25519::SigningKey.generate
  signature_key_hex = SIGNING_KEY.to_bytes.unpack1('H*')
  IO.write(KEY_FILENAME, signature_key_hex)
end

module Token

  def get_token = request.cookies[COOKIE_TOKEN_NAME]

  def clear_token
    response.set_cookie(COOKIE_TOKEN_NAME, value: '', path: '/', expires: Time.now - 3600, httponly: true)
  end

  def generate_token(external = {})
    LOGGER.debug 'Generating token ...'
    now = Time.now.to_i
    issuer = ENV['OIDC_ISSUER'].to_s
    issuer = FORWARD_OAUTH_AUTH_URL.to_s if issuer.empty? && defined?(FORWARD_OAUTH_AUTH_URL)
    issuer = issuer.sub(%r{/\z}, '')
    data = {
      iss: issuer.to_s,
      login: 'false',
      role: '',
      **external.transform_keys(&:to_sym)
    }
    subject = data[:sub] || data[:uid] || data[:login]
    data[:sub] = subject.to_s unless subject.to_s.empty?
    data[:name] = data[:login] if data[:name].to_s.empty?
    data[:email] = "#{data[:login]}@local.net" if data[:email].to_s.empty? && !data[:login].to_s.empty?
    data[:role] = data[:role].to_s
    data[:roles] = data[:role].empty? ? [] : [data[:role]]
    data[:jti] = SecureRandom.uuid
    data[:iat] = now
    data[:exp] = now + 12 * 3600
    # TODO: use alg: 'EdDSA' ED25519 is an EdDSA (Edwards-curve DSA) signature scheme. See also RFC8037 and RFC8032. )
    access_token = JWT.encode(data, SIGNING_KEY, 'EdDSA')
    response.set_cookie(COOKIE_TOKEN_NAME, value: access_token, path: '/', expires: Time.now + 12 * 3600, httponly: true)
    LOGGER.debug 'New token issued'
    access_token
  end

  def decode_token(token)
    JWT.decode(token, SIGNING_KEY.verify_key, true, { algorithm: 'EdDSA' }).first
  end

  def valid_token?(token = get_token)
    LOGGER.debug 'valid_token?'
    return false if !token || token.empty?

    decoded = decode_token(token)

    # return false unless decoded['iss'] == FORWARD_OAUTH_AUTH_URL
    unless decoded['exp'].to_i > Time.now.to_i
      LOGGER.debug 'token expired'
      return false
    end

    headers['X-Token'] = decoded.to_json
    LOGGER.debug 'token valid'
    true
  rescue => e
    LOGGER.debug "token invalid: #{LogSafety.exception_message(e)}"
    false
  end
end
