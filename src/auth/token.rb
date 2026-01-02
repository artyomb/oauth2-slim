module Token

  def get_token = request.cookies['auth_token']

  def clear_token
    response.set_cookie('auth_token', value: '', path: '/', expires: Time.now - 3600, httponly: true)
  end

  def generate_token(external = {})
    data = {
      iss: FORWARD_OAUTH_AUTH_URL.to_s,
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
    access_token
  end

  def valid_token?(token = get_token)
    return false if !token || token.empty?

    decoded = JWT.decode(token, SIGNING_KEY.verify_key, true, { algorithm: 'EdDSA' }).first

    # return false unless decoded['iss'] == FORWARD_OAUTH_AUTH_URL
    return false unless decoded['exp'].to_i > Time.now.to_i
    headers['X-Token'] = decoded
    true
  rescue StandardError => _e
    false
  end
end