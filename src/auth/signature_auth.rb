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

      context = authorization_request_context
      redirect_uri = valid_redirect_uri!(context[:redirect_uri])
      context[:redirect_uri] = redirect_uri.to_s
      auth_scope = AUTH_SCOPE || redirect_uri.host || request.env['HTTP_HOST']
      auth_scope, bot_payload = bot_auth_scope_and_payload(auth_scope) if AUTH_BOT
      authorization_fields = authorization_form_fields(context)

      signature = params[:signature]

      if valid_token? token
        decoded = decode_token token
        LOGGER.info 'AUTHORIZE BY TOKEN'
        LOGGER.info "Authorization code issued by existing token login=#{LogSafety.redact_text(decoded['login']).inspect}"
        redirect_with_authorization_code(
          auth_scope:, context:,
          identity: authorization_code_identity(decoded.transform_keys(&:to_sym))
        )
      end

      if auth_scope && signature
        verify_key = Ed25519::VerifyKey.new [AUTH_VERIFY_KEY].pack('H*')
        signature_str = Zlib::Inflate.inflate Base64.urlsafe_decode64(signature) rescue ''
        signature_fields = signature_str.split('|', -1)
        case signature_fields.length
        when 4
          scope2, time, login, sig = signature_fields
          role = nil
          message = "#{auth_scope}|#{time}|#{login}"
        when 5
          scope2, time, login, role, sig = signature_fields
          message = "#{auth_scope}|#{time}|#{login}|#{role}"
        end

        sig = [sig.to_s].pack('H*')
        t1 = scope2 == auth_scope
        t2 = Time.now.to_i - time.to_i < 30
        t3 = verify_key.verify(sig, message.to_s) rescue false

        if t1 && t2 && t3
          safe_login = LogSafety.redact_text(login).inspect
          safe_scope = LogSafety.redact_text(auth_scope).inspect
          LOGGER.info "Slim auth login successful login=#{safe_login} scope=#{safe_scope}"
          identity = { login: }
          identity[:role] = role unless role.to_s.empty?

          if params[:redirect] == 'do'
            redirect_with_authorization_code(
              auth_scope:, context:, identity:
            )
          else
            # SSO Session cookie WJT
            generate_token scope: auth_scope, **identity, sso: true
            slim :signature_auth, locals: { authorization_fields:, scope: auth_scope, bot_payload:, auth_bot: AUTH_BOT, error: nil, signature:, redirect: 'do' }, layout: false
          end
        else
          LOGGER.info "Slim auth login failed scope_match=#{t1} fresh=#{t2} signature_valid=#{t3}"
          slim :signature_auth, locals: { authorization_fields:, scope: auth_scope, bot_payload:, auth_bot: AUTH_BOT, error: 'Invalid authorization' }, layout: false
        end
      else
        slim :signature_auth, locals: { authorization_fields:, scope: auth_scope, bot_payload:, auth_bot: AUTH_BOT, error: nil }, layout: false
      end
    end
    end
  end
end
