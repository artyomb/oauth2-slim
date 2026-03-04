require 'yaml'
require 'rack/utils'

USERS_YAML = ENV['USERS_YAML']
USERS_SCOPE = ENV['AUTH_SCOPE']
FORWARD_OAUTH_AUTH_URL = ENV.fetch('FORWARD_OAUTH_AUTH_URL')

module UsersAuth
  def self.included(base)
    base.class_eval do
      helpers do
        def users_yaml_path = USERS_YAML

        def users_data
          return {} if users_yaml_path.to_s.empty?
          return {} unless File.file?(users_yaml_path)

          YAML.safe_load(File.read(users_yaml_path), permitted_classes: [], aliases: false) || {}
        rescue => e
          LOGGER.error "Cannot load USERS_YAML=#{users_yaml_path}: #{e.class}: #{e.message}"
          {}
        end

        def users_index
          entries = users_data['users']
          return {} unless entries.is_a?(Array)

          entries.each_with_object({}) do |entry, memo|
            next unless entry.is_a?(Hash)

            login, attrs = entry.first
            next if login.to_s.empty?

            attrs_hash = attrs.is_a?(Hash) ? attrs : {}
            normalized = attrs_hash.each_with_object({}) { |(k, v), h| h[k.to_s.downcase] = v }
            normalized['enabled'] = true unless normalized.key?('enabled')
            memo[login.to_s] = normalized
          end
        end

        def user_auth_attributes(login)
          user = users_index[login.to_s]
          return nil unless user
          return nil if user['enabled'] == false

          {
            login: login.to_s,
            name: user['name'],
            role: user['role'],
            org: user['org'],
            email: user['email'] || "#{login}@local.net"
          }.compact
        end

        def authorize_password(login, password)
          user = users_index[login.to_s]
          return nil unless user
          return nil if user['enabled'] == false

          expected = user['password'].to_s
          provided = password.to_s
          return nil if expected.empty?
          return nil unless expected.bytesize == provided.bytesize
          return nil unless Rack::Utils.secure_compare(expected, provided)

          user_auth_attributes(login)
        end

        def users_auth_context
          redirect_uri = params[:redirect_uri]
          uri_host = URI.parse(redirect_uri).host rescue 'host'
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
          slim :users_auth, locals: context.merge(error:), layout: false
        end
      end

      get(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
        token = get_token
        context = users_auth_context

        if valid_token?(token)
          decoded = decode_token(token)
          issue_auth_code(
            context[:scope],
            context[:redirect_uri],
            context[:state],
            {
            login: decoded['login'],
            name: decoded['name'],
            role: decoded['role'],
            org: decoded['org'],
            email: decoded['email']
            }
          )
        end

        render_users_auth(context)
      end

      post(/.*#{FORWARD_OAUTH_AUTH_URL}/) do
        context = users_auth_context

        login = (params[:login] || params[:username]).to_s.strip
        password = params[:password].to_s
        attributes = authorize_password(login, password)
        if attributes
          issue_auth_code(context[:scope], context[:redirect_uri], context[:state], attributes)
        end

        render_users_auth(context, error: 'Invalid login/password or user disabled')
      end
    end
  end
end
