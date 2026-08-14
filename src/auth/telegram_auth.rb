require 'sequel'
require 'securerandom'
require 'uri'

FORWARD_OAUTH_AUTH_URL = ENV.fetch('FORWARD_OAUTH_AUTH_URL') unless defined?(FORWARD_OAUTH_AUTH_URL)
module TelegramAuth
  TELEGRAM_AUTH_BOT = ENV.fetch('TELEGRAM_AUTH_BOT')
  AUTH_DB = Sequel.connect ENV.fetch('AUTH_DB_URL')
  AUTH_DB_QUERY = ENV.fetch('AUTH_DB_QUERY', 'SELECT * FROM t_accounts WHERE auth_code = ?')
  AUTH_SCOPE = ENV.fetch('AUTH_SCOPE')
  TOKEN_USER_FIELDS = %i[uid login name role org email].freeze

  def self.included(base)
    base.class_eval do
      before do
        session[:auth_code] ||= SecureRandom.urlsafe_base64 10
      end

      helpers do
        def tg_account
          AUTH_DB.fetch(AUTH_DB_QUERY, session[:auth_code]).all&.first
        end

        def telegram_token_attributes(account)
          values = account.to_h.transform_keys(&:to_sym)
          attributes = values.slice(*TOKEN_USER_FIELDS)
          attributes[:uid] ||= values[:id]
          halt 401, 'Telegram account login is required' if attributes[:login].to_s.strip.empty?

          attributes.compact
        end

        def issue_telegram_auth_code(account, auth_scope, context)
          identity = telegram_token_attributes(account)
          session.delete(:auth_code)
          redirect_with_authorization_code(identity:, auth_scope:, context:)
        end
      end

      get %r{.*/auth_confirm} do
        halt 404, 'Account not found' unless tg_account
      end

      get(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
        context = authorization_request_context
        redirect_uri = valid_redirect_uri!(context[:redirect_uri])
        context[:redirect_uri] = redirect_uri.to_s
        auth_scope = AUTH_SCOPE || redirect_uri.host || request.env['HTTP_HOST']

        if (account = tg_account)
          issue_telegram_auth_code(account, auth_scope, context)
        else
          slim :telegram_auth, locals: { redirect_uri: redirect_uri.to_s, state: context[:state], scope: auth_scope,
                                         auth_bot: TELEGRAM_AUTH_BOT, auth_code: session[:auth_code], error: nil }

        end
      end
    end
  end
end
