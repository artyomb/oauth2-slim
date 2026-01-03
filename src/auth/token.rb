KEY_FILENAME = ENV['RACK_ENV'] == 'production' ? '/private_keys/signing_key' : "#{__dir__}/../signing_key"
system 'mkdir -p /private_keys' if ENV['RACK_ENV'] == 'production'

if File.exist?(KEY_FILENAME)
  signature_key_hex = IO.read(KEY_FILENAME)
  SIGNING_KEY = Ed25519::SigningKey.new([signature_key_hex].pack('H*'))
else
  SIGNING_KEY = Ed25519::SigningKey.generate
  signature_key_hex = SIGNING_KEY.to_bytes.unpack1('H*')
  IO.write(KEY_FILENAME, signature_key_hex)
end

module Token

  def get_token = request.cookies['auth_token']

  def clear_token
    response.set_cookie('auth_token', value: '', path: '/', expires: Time.now - 3600, httponly: true)
  end

  def generate_token(external = {})
    LOGGER.debug 'Generating token ...'
    # Is defined only if signature_auth is used
    # Todo: fix for telegram_auth
    iss = defined?(FORWARD_OAUTH_AUTH_URL) ? FORWARD_OAUTH_AUTH_URL.to_s : ''
    data = {
      iss: iss,
      # sub: 'fake',
      login: 'false',
      role: 'fake',
      **external.transform_keys(&:to_sym),
      exp: Time.now.to_i + 12 * 3600,
      iat: Time.now.to_i
    }
    # TODO: use alg: 'EdDSA' ED25519 is an EdDSA (Edwards-curve DSA) signature scheme. See also RFC8037 and RFC8032. )
    access_token = JWT.encode(data, SIGNING_KEY, 'EdDSA')
    response.set_cookie('auth_token', value: access_token, path: '/', expires: Time.now + 12 * 3600, httponly: true)
    LOGGER.debug "New token: #{access_token}"
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
      LOGGER.debug "token expired: #{decoded}"
      return false
    end

    headers['X-Token'] = decoded
    LOGGER.debug "token valid: #{decoded}"
    true
  rescue => e
    LOGGER.debug "token invalid: #{e.message}"
    false
  end
end