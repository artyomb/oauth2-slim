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

AUTH_VERIFY_KEY = ENV['AUTH_VERIFY_KEY']
AUTH_SCOPE = ENV['AUTH_SCOPE']
AUTH_BOT = ENV['AUTH_BOT']
FORWARD_OAUTH_AUTH_URL = ENV['FORWARD_OAUTH_AUTH_URL']

module SignatureAuth
  def self.included(base)
    base.class_eval do

    get(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
      token = get_token

      redirect_uri = params[:redirect_uri]
      uri_host = URI.parse(redirect_uri).host rescue 'host'

      state = params[:state]
      state_q = state.to_s == '' ? '' : "&state=#{state}"

      scope = AUTH_SCOPE || uri_host || request.env['HTTP_HOST']

      signature = params[:signature]

      if valid_token? token
        decoded = JWT.decode(token, SIGNING_KEY.verify_key, true, { algorithm: 'EdDSA' }).first
        LOGGER.info 'AUTHORIZE BY TOKEN'
        authorization_code = SecureRandom.hex(16)
        clear_codes
        AUTH_CODES[authorization_code] = { scope:, time: Time.now.to_i, login: decoded['login']}
        LOGGER.info "AUTH_CODES[#{authorization_code}]: #{AUTH_CODES[authorization_code]}"
        LOGGER.info "REDIRECT TO: #{redirect_uri}?code=#{authorization_code}#{state_q}"

        redirect "#{redirect_uri}?code=#{authorization_code}#{state_q}"
      end

      if scope && signature
        verify_key = Ed25519::VerifyKey.new [AUTH_VERIFY_KEY].pack('H*')
        signature_str = Zlib::Inflate.inflate Base64.decode64(signature)
        scope2, time, login, sig = signature_str.split '|'
        message = "#{scope}|#{time}|#{login}"

        sig = [sig].pack('H*')
        t1 = scope2 == scope
        t2 = Time.now.to_i - time.to_i < 30
        t3 = verify_key.verify(sig, message) rescue false

        if t1 && t2 && t3
          LOGGER.info "Slim auth LOGIN Successful: #{message}"
          authorization_code = SecureRandom.hex(16)
          AUTH_CODES[authorization_code] = { scope:, time: time.to_i, login: }
          LOGGER.info "AUTH_CODES[#{authorization_code}]: #{AUTH_CODES[authorization_code]}"
          LOGGER.info "REDIRECT TO: #{redirect_uri}?code=#{authorization_code}#{state_q}"

          if params[:redirect] == 'do'
            redirect "#{redirect_uri}?code=#{authorization_code}#{state_q}"
          else
            # SSO Session cookie WJT
            generate_token scope:, login:, sso: true
            slim :signature_auth, locals: { redirect_uri:, state:, scope:, auth_bot: AUTH_BOT, error: nil, signature:, redirect: 'do' }, layout: false
          end
        else
          LOGGER.info "Slim auth LOGIN failed: #{message}"
          slim :signature_auth, locals: { redirect_uri:, state:, scope:, auth_bot: AUTH_BOT, error: 'Invalid authorization' }, layout: false
        end
      else
        slim :signature_auth, locals: { redirect_uri:, state:, scope:, auth_bot: AUTH_BOT, error: nil }, layout: false
      end
    end
    end
  end
end
