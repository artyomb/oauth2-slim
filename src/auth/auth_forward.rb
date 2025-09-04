require 'net/http'
require 'jwt'
require 'jwt/eddsa'
require 'json'
require 'digest'
require 'ed25519'
require 'faraday'

$stdout.sync=true
FORWARD_AUTH = {}

KEY_FILENAME = ENV['RACK_ENV'] == 'production' ? '/private_keys/signing_key' : "#{__dir__}/../signing_key"

if File.exist?(KEY_FILENAME)
  signature_key_hex = IO.read(KEY_FILENAME)
  SIGNING_KEY = Ed25519::SigningKey.new([signature_key_hex].pack('H*'))
else
  SIGNING_KEY = Ed25519::SigningKey.generate
  signature_key_hex = SIGNING_KEY.to_bytes.unpack1('H*')
  IO.write(KEY_FILENAME, signature_key_hex)
end

FORWARD_OAUTH_AUTH_URL = ENV['FORWARD_OAUTH_AUTH_URL']
AUTH_VERIFY_KEY = ENV['AUTH_VERIFY_KEY']
AUTH_SCOPE = ENV['AUTH_SCOPE']
AUTH_BOT = ENV['AUTH_BOT']
AUTH_CODES = {}

def forward_auth(&block)
  FORWARD_AUTH[:method] = lambda do
    instance_exec &block
  rescue => e
    $stdout.puts e.message
    halt 401, 'Unauthorized'
  end
end

module AuthForward
  FORWARD_AUTH[:method] = -> do
    path = request.env['HTTP_X_FORWARDED_URI']
    query = path[/\?(.*)/, 1].to_s.split('&state=', 2)
    parsed_params = Rack::Utils.parse_nested_query(query[0].to_s).merge({'state' => query[1]})

    code = parsed_params['code']
    if code
      LOGGER.info "FORWARD_AUTH code: #{code}"
      LOGGER.info "AUTH_CODES: #{AUTH_CODES}"
      if AUTH_CODES.key? code
        attributes = AUTH_CODES[code].slice(:scope, :login)
        generate_token attributes.merge(email: "#{attributes[:login]}@local.net")

        AUTH_CODES.delete code
        redirect parsed_params['state']
      else
        LOGGER.info "AUTH_CODES not found: #{code}"
        halt 404, "AUTH_CODES not found: #{code}"
      end
    else
      LOGGER.info "FORWARD_AUTH NO code - redirect to auth"
      proto, host, path = %w[PROTO HOST URI].map { request.env["HTTP_X_FORWARDED_#{it}"] }
      full_uri = "#{proto}://#{host}#{path}"
      full_uri_short = full_uri.split('?')[0]
      redirect "#{FORWARD_OAUTH_AUTH_URL}?redirect_uri=#{full_uri_short}&response_type=code&scope=openid+profile+email&state=#{URI.encode_www_form_component(full_uri)}", 302
    end
  end

  require_relative '../custom/forward_auth.rb' if File.exist?("#{__dir__}/../custom/forward_auth.rb")

  def self.included(base)
    base.class_eval do
      helpers do
        def generate_token(external = {})
          data = {
            iss: FORWARD_OAUTH_AUTH_URL.to_s,
            # sub: 'fake',
            login: 'false',
            role: 'fake',
            **external.transform_keys(&:to_sym),
            exp: Time.now.to_i + 12 * 3600,
            iat: Time.now.to_i
          }
          # TODO: use alg: 'EdDSA' ED25519 is an EdDSA (Edwards-curve DSA) signature scheme. See also RFC8037 and RFC8032. )
          access_token = JWT.encode(data, SIGNING_KEY, 'EdDSA')
          response.set_cookie('auth_token', value: access_token, path: '/', expires: Time.now + 12 * 3600, httponly: true)
          access_token
        end
      end

      get '/auth' do
        token = request.cookies['auth_token']
        if valid_token? token
          LOGGER.info "AUTH TOKEN VALID"
          status 200
          'OK'
        else
          LOGGER.error "AUTH TOKEN INVALID"
          instance_exec &FORWARD_AUTH[:method]
        end
      end

      get %r{.*/authorize} do
        token = request.cookies['auth_token']

        redirect_uri = params[:redirect_uri]
        r_uri = URI.parse redirect_uri
        # "#{r_uri.scheme}://#{r_uri.user}:#{r_uri.password}@#{r_uri.host}:#{r_uri.port}"

        state = params[:state]

        scope = AUTH_SCOPE || r_uri.host || request.env['HTTP_HOST']

        signature = params[:signature]

        if valid_token? token
          decoded = JWT.decode(token, SIGNING_KEY.verify_key, true, { algorithm: 'EdDSA' }).first
          LOGGER.info 'AUTHORIZE BY TOKEN'
          authorization_code = SecureRandom.hex(16)
          AUTH_CODES[authorization_code] = { scope:, time: Time.now.to_i, login: decoded['login']}
          LOGGER.info "AUTH_CODES[#{authorization_code}]: #{AUTH_CODES[authorization_code]}"
          LOGGER.info "REDIRECT TO: #{redirect_uri}?code=#{authorization_code}&state=#{state}"

          redirect "#{redirect_uri}?code=#{authorization_code}&state=#{state}"
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
            AUTH_CODES[authorization_code] = { scope:, time:, login: }
            LOGGER.info "AUTH_CODES[#{authorization_code}]: #{AUTH_CODES[authorization_code]}"
            LOGGER.info "REDIRECT TO: #{redirect_uri}?code=#{authorization_code}&state=#{state}"

            if params[:redirect] == 'do'
              redirect "#{redirect_uri}?code=#{authorization_code}&state=#{state}"
            else
              # SSO Session cookie WJT
              generate_token scope:, login:, sso: true
              slim :authorize, locals: { redirect_uri:, state:, scope:, auth_bot: AUTH_BOT, error: nil, signature:, redirect: 'do' }
            end
          else
            LOGGER.info "Slim auth LOGIN failed: #{message}"
            slim :authorize, locals: { redirect_uri:, state:, scope:, auth_bot: AUTH_BOT, error: 'Invalid authorization' }
          end
        else
          slim :authorize, locals: { redirect_uri:, state:, scope:, auth_bot: AUTH_BOT, error: nil }
        end
      end

      get '/logout' do
        response.set_cookie('auth_token', value: '', path: '/', expires: Time.now - 3600, httponly: true)
        proto = request.env['HTTP_X_FORWARDED_PROTO']
        host = request.env['HTTP_X_FORWARDED_HOST']
        uri = "#{proto}://#{host}"
        redirect uri
      end

      private

      def valid_token?(token)
        return false if !token || token.empty?

        decoded = JWT.decode(token, SIGNING_KEY.verify_key, true, { algorithm: 'EdDSA' }).first

        # return false unless decoded['iss'] == FORWARD_OAUTH_AUTH_URL
        return false unless decoded['exp'].to_i > Time.now.to_i
        headers['X-Token'] = decoded
        true
      rescue StandardError => _e
        false
      end

    end
  end
end
