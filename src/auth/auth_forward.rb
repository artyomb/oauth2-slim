require 'net/http'
require 'jwt'
require 'jwt/eddsa'
require 'json'
require 'digest'
require 'ed25519'
require 'faraday'
require 'rack/utils'
require_relative 'token'

$stdout.sync=true
FORWARD_AUTH = {}
AUTH_CODES = {}
def clear_codes
  AUTH_CODES.delete_if { |k, v| v[:time] < Time.now.to_i - 30 }
end

# CUSTOM override forward auth method:
#
# config target: '/app/custom/forward_auth.rb', file_content: <<~RUBY
#   forward_auth do
#     me = Faraday.new { |f| f.response :raise_error }.get('#{FORWARD_AUTH_SERVER}') do |r|
#       r.headers['Cookie'] = request.cookies.map { |k, v| "\#{k}=\#{v}" }.join('; ')
#     end
#
#    generate_token user_id: me[:id]
#   end
# RUBY
def forward_auth(&block)
  FORWARD_AUTH[:method] = lambda do
    LOGGER.debug 'Custom forward_auth method'
    instance_exec &block
  rescue => e
    LOGGER.error "Error in Custom forward_auth method: #{LogSafety.exception_message(e)}"
    halt 401, 'Unauthorized'
  end
end

def revoked?(&block)
  FORWARD_AUTH[:revoked?] = lambda do
    instance_exec &block
  rescue => e
    LOGGER.error "Error in is_revoked?: #{LogSafety.exception_message(e)}"
    raise
  end
end

module AuthForward
  OWNED_IDENTITY_HEADERS = %w[x-authslim x-token].freeze

  require_relative '../custom/forward_auth.rb' if File.exist?("#{__dir__}/../custom/forward_auth.rb")

  def self.included(base)
    base.class_eval do
      helpers Token

      if ENV['USERS_DB_URL'].to_s != '' && FORWARD_AUTH[:method].nil?
        LOGGER.info 'DBUserAuth'
        require_relative 'db_user_auth'
        helpers DBUserAuth
      end

      if ENV['USERS_YAML'].to_s != '' && File.file?(ENV['USERS_YAML']) && FORWARD_AUTH[:method].nil?
        LOGGER.info 'UsersAuth'
        require_relative 'users_auth'
        helpers UsersAuth
      end

      if ENV['AUTH_VERIFY_KEY'] && FORWARD_AUTH[:method].nil?
        LOGGER.info 'SignatureAuth'
        require_relative 'signature_auth'
        helpers SignatureAuth
      end

      if ENV['TELEGRAM_AUTH_BOT'] && FORWARD_AUTH[:method].nil?
        LOGGER.info 'TelegramAuth'
        require_relative 'telegram_auth'
        helpers TelegramAuth
      end

      FORWARD_AUTH[:revoked?] ||= -> { false }
      FORWARD_AUTH[:method] ||= -> do
        proto = request.env['HTTP_X_FORWARDED_PROTO'] || request.env['rack.url_scheme']
        host = request.env['HTTP_X_FORWARDED_HOST'] || request.env['HTTP_HOST']
        path = request.env['HTTP_X_FORWARDED_URI'] || request.env['REQUEST_URI']
        full_uri = "#{proto}://#{host}#{path}"
        full_uri_short, to_params = full_uri.split('?')

        LOGGER.info 'FORWARD_AUTH NO code - redirect to auth'
        params = {
          redirect_uri: full_uri_short,
          response_type: 'code',
          scope: 'openid profile email'
        }
        params[:state] = Base64.urlsafe_encode64(to_params) unless to_params.to_s.empty?
        headers['X-Redirect-Reason'] = 'unauthorized'
        redirect "#{FORWARD_OAUTH_AUTH_URL}?#{URI.encode_www_form(params)}", 302
      end

      def authorization_endpoint_uri
        @authorization_endpoint_uri ||= URI.parse(FORWARD_OAUTH_AUTH_URL.to_s)
      rescue URI::InvalidURIError
        nil
      end

      def valid_redirect_uri!(redirect_uri)
        halt 400, 'redirect_uri is required' if redirect_uri.to_s.empty?

        uri = URI.parse(redirect_uri)
        halt 400, 'redirect_uri must use http or https' unless %w[http https].include?(uri.scheme)
        halt 400, 'redirect_uri host is required' if uri.host.to_s.empty?

        auth_uri = authorization_endpoint_uri
        auth_path = auth_uri&.path.to_s.empty? ? FORWARD_OAUTH_AUTH_URL.to_s : auth_uri.path.to_s
        same_path = uri.path.to_s == auth_path
        same_host = auth_uri.nil? || auth_uri.host.to_s.empty? || auth_uri.host == uri.host

        if same_path && same_host
          LOGGER.warn "Rejected recursive redirect_uri: #{LogSafety.redact_url(redirect_uri)}"
          halt 400, 'redirect_uri must not point to the authorization endpoint'
        end

        uri
      rescue URI::InvalidURIError
        halt 400, 'redirect_uri is invalid'
      end

      # todo: Maybe narrow which headers get forwarded (e.g., only X-*).
      def forward_incoming_headers
        request.env.each do |key, value|
          next unless key.start_with?('HTTP_') || key == 'CONTENT_TYPE' || key == 'CONTENT_LENGTH'

          header_name = key.sub(/^HTTP_/, '').split('_').map(&:capitalize).join('-')
          next if %w[Connection Keep-Alive Proxy-Authenticate Proxy-Authorization Te Trailer Transfer-Encoding Upgrade].include?(header_name)
          next if OWNED_IDENTITY_HEADERS.include?(header_name.downcase)

          headers[header_name] = value
        end
      end

      def forward_auth_params
        raw_uri = request.env['HTTP_X_FORWARDED_URI'] || request.env['REQUEST_URI'] || ''
        query = raw_uri.split('?', 2)[1].to_s
        Rack::Utils.parse_nested_query(query)
      end

      def complete_forward_auth(code, x_params)
        LOGGER.info 'FORWARD_AUTH code received'
        clear_codes
        halt 404, 'AUTH code not found' unless AUTH_CODES.key? code

        attributes = AUTH_CODES[code].slice(:scope, :uid, :login, :name, :role, :org, :email)
        attributes[:email] ||= "#{attributes[:login]}@local.net" if attributes[:login]
        generate_token attributes
        AUTH_CODES.delete code

        proto = request.env['HTTP_X_FORWARDED_PROTO'] || request.env['rack.url_scheme']
        host = request.env['HTTP_X_FORWARDED_HOST'] || request.env['HTTP_HOST']
        path = request.env['HTTP_X_FORWARDED_URI'] || request.env['REQUEST_URI']
        full_uri_short = "#{proto}://#{host}#{path}".split('?').first
        state = x_params['state'].to_s
        state_q = state.empty? ? '' : "?#{Base64.urlsafe_decode64 state}"
        LOGGER.info 'FORWARD_AUTH state restored' unless state.empty?
        redirect full_uri_short + state_q
      end

      def handle_forward_auth_request(optional:)
        x_params = forward_auth_params
        LOGGER.debug "Forward auth query received: #{LogSafety.redact_hash(x_params)}"

        return complete_forward_auth(x_params['code'], x_params) if x_params.key? 'code'

        authenticated = valid_token?
        authenticated &&= !FORWARD_AUTH[:revoked?].call
        if authenticated
          LOGGER.info 'AUTH TOKEN VALID'
          forward_incoming_headers
          headers['X-AuthSlim'] = 'authorized'
          return status 200
        end

        headers.delete 'X-Token'
        if optional
          LOGGER.info 'Optional forward auth allowed anonymous request'
          forward_incoming_headers
          headers.delete 'X-AuthSlim'
          return status 200
        end

        instance_exec &FORWARD_AUTH[:method]
        forward_incoming_headers
        headers['X-AuthSlim'] = 'authorized'
        LOGGER.info 'Authorization successful'
      end

      def logout
        clear_token
        session.delete(:auth_code) if session.key?(:auth_code)
        cache_control :no_cache, :no_store, :must_revalidate
        headers['Pragma'] = 'no-cache'
        headers['Expires'] = '0'
      end

      def logout_redirect_uri
        proto = request.env['HTTP_X_FORWARDED_PROTO'] || request.scheme
        host = request.env['HTTP_X_FORWARDED_HOST'] || request.host_with_port
        "#{proto}://#{host}"
      end

      get('/auth') { handle_forward_auth_request(optional: false) }
      get('/auth/optional') { handle_forward_auth_request(optional: true) }

      get %r{.*/logout} do
        logout
        redirect logout_redirect_uri
      end

    end
  end
end
