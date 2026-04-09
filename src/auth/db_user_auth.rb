require 'sequel'
require 'uri'
require 'json'

USERS_DB_URL = ENV['USERS_DB_URL']
USERS_DB_QUERY = ENV.fetch(
  'USERS_DB_QUERY',
  'SELECT login, name, role, org, email, enabled FROM users WHERE login = ? AND enabled = TRUE AND password_hash = crypt(?, password_hash) LIMIT 1'
)
USERS_SCOPE = ENV['AUTH_SCOPE']
FORWARD_OAUTH_AUTH_URL = ENV.fetch('FORWARD_OAUTH_AUTH_URL')
DB_USER_ADMIN_PATH = ENV.fetch('DB_USER_ADMIN_PATH', '/admin/users')
USER_FIELDS = %i[login name role org email enabled].freeze
TOKEN_FIELDS = %i[login name role org email].freeze
DB_USER_AUTH_PATH = begin
  uri = URI.parse(FORWARD_OAUTH_AUTH_URL.to_s)
  uri.path.to_s.empty? ? FORWARD_OAUTH_AUTH_URL.to_s : uri.path.to_s
rescue URI::InvalidURIError
  FORWARD_OAUTH_AUTH_URL.to_s
end

module DBUserAuth
  def self.included(base)
    base.class_eval do
      helpers do
        def users_db
          @users_db ||= Sequel.connect(USERS_DB_URL).tap { _1.run('CREATE EXTENSION IF NOT EXISTS pgcrypto') }
        end

        def normalize_user_record(record)
          return nil unless record.is_a?(Hash)

          record.each_with_object({}) do |(key, value), memo|
            memo[key.to_s.downcase] = value
          end
        end

        def users_dataset
          users_db[:users]
        end

        def current_auth_user
          token = get_token
          return nil unless valid_token?(token)

          decode_token(token)
        rescue StandardError
          nil
        end

        def admin_redirect_uri
          scheme = request.env['HTTP_X_FORWARDED_PROTO'] || request.scheme
          host = request.env['HTTP_X_FORWARDED_HOST'] || request.host_with_port
          "#{scheme}://#{host}#{DB_USER_ADMIN_PATH}"
        end

        def complete_admin_code_flow!(code)
          clear_codes
          halt 404, "AUTH_CODES not found: #{code}" unless AUTH_CODES.key?(code)

          attributes = AUTH_CODES[code].slice(:scope, *TOKEN_FIELDS)
          attributes[:email] ||= "#{attributes[:login]}@local.net" if attributes[:login]
          generate_token attributes
          AUTH_CODES.delete code
          redirect admin_redirect_uri
        end

        def require_admin_user!
          user = current_auth_user
          redirect "#{FORWARD_OAUTH_AUTH_URL}?#{URI.encode_www_form(redirect_uri: admin_redirect_uri, response_type: 'code', scope: USERS_SCOPE || request.host)}" unless user
          halt 403, 'Admin role required' unless user && user['role'].to_s == 'admin'
        end

        def render_admin_json(status: 200, notice: nil, error: nil, users: nil)
          content_type :json
          halt status, JSON.generate({ notice:, error:, users: }.compact)
        end

        def respond_admin_success(message)
          render_admin_json(notice: message, users: managed_users)
        end

        def respond_admin_error(message, status: 422)
          render_admin_json(status: status, error: message)
        end

        def admin_error!(message, status: 422)
          respond_admin_error(message, status:)
        end

        def user_row_attributes(record)
          USER_FIELDS.each_with_object({}) do |field, attrs|
            value = record[field]
            attrs[field] = field == :enabled ? value != false : value.to_s
          end
        end

        def managed_users
          users_dataset.select(*USER_FIELDS).order(:login).all.map { |record| user_row_attributes(record) }
        end

        def require_user!(login)
          admin_error!('login is required', status: 400) if login.to_s.strip.empty?

          record = users_dataset.where(login: login.to_s).first
          admin_error!("User not found: #{login}", status: 404) unless record

          user_row_attributes(record)
        end

        def user_params(*keys)
          keys.to_h { |key| [key, params[key].to_s.strip] }
        end

        def password_hash(value)
          Sequel.lit("crypt(?, gen_salt('bf'))", value.to_s)
        end

        def user_insert_attributes(attrs)
          {
            **attrs.slice(:login, :name, :role, :org, :email),
            password_hash: password_hash(attrs[:password]),
            enabled: true
          }
        end

        def db_user(login, password)
          return nil if [USERS_DB_URL, login, password].any? { |value| value.to_s.empty? }

          normalize_user_record(users_db.fetch(USERS_DB_QUERY, login.to_s, password.to_s).first)
        rescue => e
          LOGGER.error "Cannot fetch DB user login=#{login}: #{e.class}: #{e.message}"
          nil
        end

        def authorize_password(login, password)
          user = db_user(login, password)
          return nil unless user

          token_attributes(user, fallback_login: login)
        end

        def users_auth_context
          redirect_uri = params[:redirect_uri]
          uri_host = valid_redirect_uri!(redirect_uri).host
          state = params[:state]
          scope = USERS_SCOPE || uri_host || request.env['HTTP_HOST']
          { redirect_uri:, state:, scope: }
        end

        def state_query(state)
          state.to_s == '' ? '' : "&state=#{state}"
        end

        def issue_auth_code(scope, redirect_uri, state, attributes)
          authorization_code = SecureRandom.hex(16)
          clear_codes
          AUTH_CODES[authorization_code] = { scope:, time: Time.now.to_i, **attributes }.compact
          redirect "#{redirect_uri}?code=#{authorization_code}#{state_query(state)}"
        end

        def token_attributes(user, fallback_login: nil)
          login = (user['login'] || fallback_login).to_s
          { login:, name: user['name'], role: user['role'], org: user['org'], email: user['email'] || "#{login}@local.net" }.compact
        end

        def with_db_error(message)
          yield
        rescue Sequel::DatabaseError => e
          LOGGER.error "#{message}: #{e.class}: #{e.message}"
          respond_admin_error(e.message)
        end

        def admin_db_action(message)
          require_admin_user!
          with_db_error(message) { yield }
        end

      end

      get DB_USER_AUTH_PATH do
        token = get_token
        context = users_auth_context

        issue_auth_code(context[:scope], context[:redirect_uri], context[:state], token_attributes(decode_token(token))) if valid_token?(token)

        slim :users_auth, locals: context
      end

      post DB_USER_AUTH_PATH do
        context = users_auth_context

        login = (params[:login] || params[:username]).to_s.strip
        password = params[:password].to_s
        attributes = authorize_password(login, password)
        if attributes
          issue_auth_code(context[:scope], context[:redirect_uri], context[:state], attributes)
        end

        slim :users_auth, locals: context.merge(error: 'Invalid login/password or user disabled')
      end

      get DB_USER_ADMIN_PATH do
        complete_admin_code_flow!(params[:code]) if params[:code]
        require_admin_user!
        slim :db_users_admin, locals: { users: managed_users, admin_path: DB_USER_ADMIN_PATH }
      end

      get "#{DB_USER_ADMIN_PATH}/data" do
        require_admin_user!
        render_admin_json(users: managed_users)
      end

      post DB_USER_ADMIN_PATH do
        admin_db_action("Cannot create DB user login=#{params[:login]}") do
          attrs = { **user_params(:login, :name, :role, :org, :email), password: params[:password].to_s }
          admin_error!('login is required', status: 400) if attrs[:login].empty?
          admin_error!('password is required', status: 400) if attrs[:password].empty?
          admin_error!("User already exists: #{attrs[:login]}", status: 409) if users_dataset.where(login: attrs[:login]).count.positive?

          users_dataset.insert(user_insert_attributes(attrs))
          respond_admin_success("User #{attrs[:login]} created")
        end
      end

      post "#{DB_USER_ADMIN_PATH}/:login" do |login|
        admin_db_action("Cannot update DB user login=#{login}") do
          require_user!(login)
          users_dataset.where(login: login).update(user_params(:name, :role, :org, :email))
          respond_admin_success("User #{login} updated")
        end
      end

      post "#{DB_USER_ADMIN_PATH}/:login/password" do |login|
        admin_db_action("Cannot update DB user password login=#{login}") do
          require_user!(login)
          admin_error!('password is required', status: 400) if params[:password].to_s.empty?
          users_dataset.where(login: login.to_s).update(password_hash: password_hash(params[:password]))
          respond_admin_success("Password updated for #{login}")
        end
      end

      post "#{DB_USER_ADMIN_PATH}/:login/delete" do |login|
        admin_db_action("Cannot delete DB user login=#{login}") do
          require_user!(login)
          users_dataset.where(login: login).delete
          respond_admin_success("User #{login} deleted")
        end
      end

    end
  end
end
