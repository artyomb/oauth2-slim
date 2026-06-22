require 'sequel'
require 'uri'
require 'json'
require_relative 'log_safety'

USERS_DB_URL = ENV['USERS_DB_URL']
USERS_SCOPE = ENV['AUTH_SCOPE']
FORWARD_OAUTH_AUTH_URL = ENV.fetch('FORWARD_OAUTH_AUTH_URL')
DB_USER_ADMIN_PATH = ENV.fetch('DB_USER_ADMIN_PATH', '/admin/users')
DB_USER_SEED = ENV.fetch('DB_USER_SEED', 'false') == 'true'
DB_USER_SEED_LOGIN = ENV.fetch('DB_USER_SEED_LOGIN', 'admin')
DB_USER_SEED_PASSWORD = ENV['DB_USER_SEED_PASSWORD']
DB_PASSWORD_COST = Integer(ENV.fetch('DB_PASSWORD_COST', '12'))
BCRYPT_MAX_PASSWORD_BYTES = 72
USER_FIELDS = %i[login name role org email].freeze
TOKEN_USER_FIELDS = %i[uid login name role org email].freeze

raise 'DB_PASSWORD_COST must be between 10 and 31' unless (10..31).cover?(DB_PASSWORD_COST)
raise 'DB_USER_SEED_LOGIN is required when DB_USER_SEED=true' if DB_USER_SEED && DB_USER_SEED_LOGIN.to_s.empty?
raise 'DB_USER_SEED_PASSWORD is required when DB_USER_SEED=true' if DB_USER_SEED && DB_USER_SEED_PASSWORD.to_s.empty?
raise "DB_USER_SEED_PASSWORD is too long; maximum is #{BCRYPT_MAX_PASSWORD_BYTES} bytes" if DB_USER_SEED && DB_USER_SEED_PASSWORD.to_s.bytesize > BCRYPT_MAX_PASSWORD_BYTES

DB = Sequel.connect(USERS_DB_URL)
DB.extension :connection_validator
DB.pool.connection_validation_timeout = ENV.fetch('DB_CONNECTION_VALIDATION_TIMEOUT', '60').to_i
DB.run 'CREATE EXTENSION IF NOT EXISTS pgcrypto'
DB.create_table? :oauth_users do
  primary_key :id
  String :login, unique: true, null: false
  String :password_hash, null: false
  String :name, null: true
  String :role, null: true
  String :org, null: true
  String :email, null: true
  DateTime :created_at, null: false, default: Sequel.lit('NOW()')
  DateTime :updated_at, null: false, default: Sequel.lit('NOW()')
  DateTime :deleted_at, null: true
end

oauth_user_columns = DB.schema(:oauth_users).map(&:first)
if oauth_user_columns.include?(:password) && !oauth_user_columns.include?(:password_hash)
  DB.alter_table(:oauth_users) do
    rename_column :password, :password_hash
  end
end

class OAuthUser < Sequel::Model(:oauth_users)
  plugin :validation_helpers
  plugin :timestamps, create: :created_at, update: :updated_at, update_on_create: true
end

if DB_USER_SEED
  seed_hash = Sequel.lit("crypt(?, gen_salt('bf', ?))", DB_USER_SEED_PASSWORD, DB_PASSWORD_COST)
  OAuthUser.insert(login: DB_USER_SEED_LOGIN, password_hash: seed_hash, name: DB_USER_SEED_LOGIN, role: 'admin', email: "#{DB_USER_SEED_LOGIN}@local.net") unless OAuthUser.where(login: DB_USER_SEED_LOGIN).count.positive?
end

module DBUserAuth
  def self.included(base)
    base.class_eval do
      helpers do
        def current_auth_user
          token = get_token
          return nil unless valid_token?(token)

          decode_token(token).transform_keys(&:to_sym)
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
          halt 404, 'AUTH code not found' unless AUTH_CODES.key?(code)

          attributes = AUTH_CODES[code].slice(:scope, *TOKEN_USER_FIELDS)
          attributes[:email] ||= "#{attributes[:login]}@local.net" if attributes[:login]
          generate_token attributes
          AUTH_CODES.delete code
          redirect admin_redirect_uri
        end

        def require_admin_user!
          user = current_auth_user
          redirect "#{FORWARD_OAUTH_AUTH_URL}?#{URI.encode_www_form(redirect_uri: admin_redirect_uri, response_type: 'code', scope: USERS_SCOPE || request.host)}" unless user
          halt 403, 'Admin role required' unless user && user[:role].to_s == 'admin'
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
          USER_FIELDS.each_with_object({}) { |field, attrs| attrs[field] = record[field].to_s }
        end

        def managed_users
          OAuthUser.select(*USER_FIELDS).order(:login).all.map { |record| user_row_attributes(record) }
        end

        def require_user!(login)
          admin_error!('login is required', status: 400) if login.to_s.strip.empty?

          record = OAuthUser.where(login: login.to_s).first
          admin_error!("User not found: #{login}", status: 404) unless record

          user_row_attributes(record)
        end

        def user_params(*keys)
          keys.to_h { |key| [key, params[key].to_s.strip] }
        end

        def password_too_long?(value)
          value.to_s.bytesize > BCRYPT_MAX_PASSWORD_BYTES
        end

        def validate_password!(value)
          admin_error!("password is too long; maximum is #{BCRYPT_MAX_PASSWORD_BYTES} bytes", status: 400) if password_too_long?(value)
        end

        def password_hash(value)
          Sequel.lit("crypt(?, gen_salt('bf', ?))", value.to_s, DB_PASSWORD_COST)
        end

        def db_user(login, password)
          return nil if [USERS_DB_URL, login, password].any? { |value| value.to_s.empty? }
          return nil if password_too_long?(password)

          OAuthUser.select(:id, *USER_FIELDS).where(login: login.to_s).where(Sequel.lit('password_hash = crypt(?, password_hash)', password.to_s)).first
        rescue => e
          LOGGER.error "Cannot fetch DB user login=#{login}: #{LogSafety.exception_message(e)}"
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

        def render_users_auth(context, error: nil)
          slim :users_auth, locals: context.merge(error:)
        end

        def token_attributes(user, fallback_login: nil)
          login = (user[:login] || fallback_login).to_s
          { uid: user[:id], login:, name: user[:name], role: user[:role], org: user[:org], email: user[:email] || "#{login}@local.net" }.compact
        end

        def with_db_error(message)
          yield
        rescue Sequel::DatabaseError => e
          LOGGER.error "#{message}: #{LogSafety.exception_message(e)}"
          respond_admin_error('Database operation failed')
        end

        def admin_db_action(message)
          require_admin_user!
          with_db_error(message) { yield }
        end

      end

      get(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
        token = get_token
        context = users_auth_context
        clear_legacy_tokens

        issue_auth_code(context[:scope], context[:redirect_uri], context[:state], token_attributes(current_auth_user)) if valid_token?(token)

        render_users_auth(context)
      end

      post(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
        context = users_auth_context
        clear_legacy_tokens

        login = (params[:login] || params[:username]).to_s.strip
        password = params[:password].to_s
        attributes = authorize_password(login, password)
        if attributes
          issue_auth_code(context[:scope], context[:redirect_uri], context[:state], attributes)
        end

        render_users_auth(context, error: 'Invalid login/password or user disabled')
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
          validate_password!(attrs[:password])
          admin_error!("User already exists: #{attrs[:login]}", status: 409) if OAuthUser.where(login: attrs[:login]).count.positive?

          OAuthUser.insert({ **attrs.slice(:login, :name, :role, :org, :email), password_hash: password_hash(attrs[:password]) })
          respond_admin_success("User #{attrs[:login]} created")
        end
      end

      post "#{DB_USER_ADMIN_PATH}/:login" do |login|
        admin_db_action("Cannot update DB user login=#{login}") do
          require_user!(login)
          OAuthUser.where(login: login).update(user_params(:name, :role, :org, :email))
          respond_admin_success("User #{login} updated")
        end
      end

      post "#{DB_USER_ADMIN_PATH}/:login/password" do |login|
        admin_db_action("Cannot update DB user password login=#{login}") do
          require_user!(login)
          admin_error!('password is required', status: 400) if params[:password].to_s.empty?
          validate_password!(params[:password])
          OAuthUser.where(login: login.to_s).update(password_hash: password_hash(params[:password]))
          respond_admin_success("Password updated for #{login}")
        end
      end

      post "#{DB_USER_ADMIN_PATH}/:login/delete" do |login|
        admin_db_action("Cannot delete DB user login=#{login}") do
          require_user!(login)
          OAuthUser.where(login: login).delete
          respond_admin_success("User #{login} deleted")
        end
      end

    end
  end
end
