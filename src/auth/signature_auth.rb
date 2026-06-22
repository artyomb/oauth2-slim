require 'base64'
require_relative 'domain_payload.rb'
require_relative 'log_safety'

AUTH_VERIFY_KEY = ENV['AUTH_VERIFY_KEY']
AUTH_SCOPE = ENV['AUTH_SCOPE']
AUTH_BOT = ENV['AUTH_BOT']
FORWARD_OAUTH_AUTH_URL = ENV['FORWARD_OAUTH_AUTH_URL']

module SignatureAuth
  def self.included(base)
    base.class_eval do
    def bot_auth_scope_and_payload(scope)
      payload = DomainPayload.encode(scope)
      [DomainPayload.decode(payload), payload]
    rescue ArgumentError
      [scope, Base64.urlsafe_encode64(scope.to_s, padding: false)]
    end

    get(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
      token = get_token

      redirect_uri = params[:redirect_uri]
      uri_host = valid_redirect_uri!(redirect_uri).host

      state = params[:state]
      state_q = state.to_s == '' ? '' : "&state=#{state}"

      scope = AUTH_SCOPE || uri_host || request.env['HTTP_HOST']
      scope, bot_payload = bot_auth_scope_and_payload(scope) if AUTH_BOT

      signature = params[:signature]

      if valid_token? token
        decoded = decode_token token
        LOGGER.info 'AUTHORIZE BY TOKEN'
        authorization_code = SecureRandom.hex(16)
        clear_codes
        AUTH_CODES[authorization_code] = { scope:, time: Time.now.to_i, login: decoded['login']}
        LOGGER.info "Authorization code issued by existing token login=#{LogSafety.redact_text(decoded['login']).inspect}"

        redirect "#{redirect_uri}?code=#{authorization_code}#{state_q}"
      end

      if scope && signature
        verify_key = Ed25519::VerifyKey.new [AUTH_VERIFY_KEY].pack('H*')
        signature_str = Zlib::Inflate.inflate Base64.urlsafe_decode64(signature) rescue ''
        scope2, time, login, sig = signature_str.split '|'
        message = "#{scope}|#{time}|#{login}"

        sig = [sig].pack('H*')
        t1 = scope2 == scope
        t2 = Time.now.to_i - time.to_i < 30
        t3 = verify_key.verify(sig, message) rescue false

        if t1 && t2 && t3
          safe_login = LogSafety.redact_text(login).inspect
          safe_scope = LogSafety.redact_text(scope).inspect
          LOGGER.info "Slim auth login successful login=#{safe_login} scope=#{safe_scope}"
          authorization_code = SecureRandom.hex(16)
          AUTH_CODES[authorization_code] = { scope:, time: time.to_i, login: }

          if params[:redirect] == 'do'
            redirect "#{redirect_uri}?code=#{authorization_code}#{state_q}"
          else
            # SSO Session cookie WJT
            generate_token scope:, login:, sso: true
            slim :signature_auth, locals: { redirect_uri:, state:, scope:, bot_payload:, auth_bot: AUTH_BOT, error: nil, signature:, redirect: 'do' }, layout: false
          end
        else
          LOGGER.info "Slim auth login failed scope_match=#{t1} fresh=#{t2} signature_valid=#{t3}"
          slim :signature_auth, locals: { redirect_uri:, state:, scope:, bot_payload:, auth_bot: AUTH_BOT, error: 'Invalid authorization' }, layout: false
        end
      else
        slim :signature_auth, locals: { redirect_uri:, state:, scope:, bot_payload:, auth_bot: AUTH_BOT, error: nil }, layout: false
      end
    end
    end
  end
end
