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
    LOGGER.error 'Error in Custom forward_auth method: ', e
    halt 401, 'Unauthorized'
  end
end

def revoked?(&block)
  FORWARD_AUTH[:revoked?] = lambda do
    instance_exec &block
  rescue => e
    LOGGER.error 'Error in is_revoked?: ', e
    raise
  end
end

module AuthForward
  require_relative '../custom/forward_auth.rb' if File.exist?("#{__dir__}/../custom/forward_auth.rb")

  def self.included(base)
    base.class_eval do
      helpers Token

      if ENV['AUTH_VERIFY_KEY'] && FORWARD_AUTH[:method].nil?
        require_relative 'signature_auth'
        helpers SignatureAuth
      end

      if ENV['TELEGRAM_AUTH_BOT'] && FORWARD_AUTH[:method].nil?
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

        state = to_params.to_s == '' ? '' : "&state=#{Base64.urlsafe_encode64(to_params)}"
        LOGGER.info 'FORWARD_AUTH NO code - redirect to auth'
        params = {
          redirect_uri: full_uri_short,
          response_type: 'code',
          scope: 'openid profile email',
          state: state
        }
        redirect "#{FORWARD_OAUTH_AUTH_URL}?#{URI.encode_www_form(params)}", 302
      end

      get '/auth' do
        # force ?code= detect even token is valid ...
        raw_uri = request.env['HTTP_X_FORWARDED_URI'] || request.env['REQUEST_URI'] || ''
        query = raw_uri.split('?', 2)[1].to_s
        x_params = Rack::Utils.parse_nested_query(query)
        LOGGER.debug :x_params, x_params

        if valid_token? && !FORWARD_AUTH[:revoked?].call && !x_params['code']
          LOGGER.info 'AUTH TOKEN VALID'
          status 200
        else
          code = x_params['code']
          if code
            LOGGER.info "FORWARD_AUTH code: #{code}"
            clear_codes
            if AUTH_CODES.key? code
              attributes = AUTH_CODES[code].slice(:scope, :login)
              generate_token attributes.merge(email: "#{attributes[:login]}@local.net")

              AUTH_CODES.delete code
              proto = request.env['HTTP_X_FORWARDED_PROTO'] || request.env['rack.url_scheme']
              host = request.env['HTTP_X_FORWARDED_HOST'] || request.env['HTTP_HOST']
              path = request.env['HTTP_X_FORWARDED_URI'] || request.env['REQUEST_URI']
              full_uri = "#{proto}://#{host}#{path}"
              full_uri_short = full_uri.split('?').first

              state = x_params['state'] || ''
              state_q = state.to_s == '' ? '' : "?#{Base64.urlsafe_decode64 state}"
              LOGGER.info "state: #{state}, state_q: #{state_q}"
              redirect full_uri_short + state_q
            else
              halt 404, "AUTH_CODES not found: #{code}"
            end
          end

          instance_exec &FORWARD_AUTH[:method]
          headers['X-AuthSlim'] = 'authorized'
          LOGGER.info 'Authorization successful'
        end
      end

      get %r{.*/logout} do
        clear_token

        proto = request.env['HTTP_X_FORWARDED_PROTO']
        host = request.env['HTTP_X_FORWARDED_HOST']
        uri = "#{proto}://#{host}"
        redirect uri
      end

    end
  end
end
