require 'sequel'

module TelegramAuth
  TELEGRAM_AUTH_BOT = ENV.fetch('TELEGRAM_AUTH_BOT')
  AUTH_DB = Sequel.connect ENV.fetch('AUTH_DB_URL')
  AUTH_DB_QUERY = ENV.fetch('AUTH_DB_QUERY', 'SELECT * FROM t_accounts WHERE auth_code = ?')
  FORWARD_OAUTH_AUTH_URL = ENV.fetch('FORWARD_OAUTH_AUTH_URL')
  AUTH_SCOPE = ENV.fetch('AUTH_SCOPE')

  def self.included(base)
    base.class_eval do
      before do
        session[:auth_code] ||= SecureRandom.urlsafe_base64 10
      end

      helpers do
        def tg_account
          AUTH_DB.fetch(AUTH_DB_QUERY, session[:auth_code]).all&.first
        end
      end

      get %r{.*/auth_confirm} do
        halt 404, 'Account not found' unless tg_account
      end

      get(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
        redirect_uri = params[:redirect_uri]
        uri_host = URI.parse(redirect_uri).host rescue 'host'

        state = params[:state] rescue nil
        scope = AUTH_SCOPE || uri_host || request.env['HTTP_HOST']

        if tg_account
          redirect_uri += "?#{state}" if state.to_s.any?
          redirect redirect_uri
        else
          slim :telegram_auth, locals: { redirect_uri:, state:, scope:,
                                         auth_bot: TELEGRAM_AUTH_BOT, auth_code: session[:auth_code], error: nil }

        end
      end
    end
  end
end
