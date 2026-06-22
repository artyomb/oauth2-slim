require_relative 'ajax'
require_relative 'log_safety'

module Auth20
  def self.included(base)
    base.class_eval do
      helpers Ajax::Helpers

      before do
        # unless request.path_info =~ /login|\/api|favicon/
        #   halt 401 if (request.path_info =~ /\/oauth_back\/me/) && request.cookies['authenticated'].nil?
        #   redirect '/oauth_back/login' if request.cookies['authenticated'].nil?
        #   # redirect '/login' if request.cookies['authenticated'].nil? && request.path_info != '/login'
        # end
        # if request.path_info =~ /\/api/
        #   # initialize
        # end
      end

      after do
        if request.path_info =~ /\/api/
          # @kc.logout
        end
      end

      helpers do
        def bearer_token
          request.env['HTTP_AUTHORIZATION'].to_s[/\ABearer\s+(.+)\z/i, 1]
        end

        def userinfo_token = bearer_token || get_token

        def userinfo_payload
          token = userinfo_token
          halt 401, 'Bearer token or auth cookie required' if token.to_s.empty?

          decode_token(token)
        rescue JWT::DecodeError => e
          LOGGER.debug "Invalid userinfo token: #{e.class}"
          halt 401, 'Invalid token'
        end
      end

      post %r{.*/token_old} do
        LOGGER.warn 'Deprecated token_old endpoint requested'
        halt 410, 'Deprecated token endpoint'
      end

      post %r{.*/token} do
        code = params['code']
        halt 400, 'Invalid code' if code.to_s.empty?

        unless AUTH_CODES.key? code
          LOGGER.warn 'OAuth token exchange failed: authorization code not found'
          halt 404, 'Authorization code not found'
        end

        attributes = AUTH_CODES[code].slice(:scope, :uid, :login, :name, :role, :org, :email)
        AUTH_CODES.delete code

        attributes[:email] ||= "#{attributes[:login]}@local.net" if attributes[:login]
        subject = attributes[:uid] || attributes[:login]
        attributes[:sub] ||= subject.to_s unless subject.to_s.empty?
        access_token = generate_token attributes
        content_type :json
        {
          "access_token": access_token,
          'token_type': 'Bearer',
          "token_format": 'jwt',
          "token_algorithm": 'RS256',
          'expires_in': 3600,
          'refresh_token': 'refresh_token',
          'scope': 'allowed_scopes'
        }.to_json
      end

      get %r{.*/user} do
        access_token = userinfo_payload

        content_type :json
        subject = access_token['sub'] || access_token['uid'] || access_token['login']
        {
          sub: subject.to_s,
          admin: 'admin',
          login: access_token['login'],
          role: access_token['role'] || 'admin',
          name: access_token['name'],
          org: access_token['org'],
          email: access_token['email']
        }.to_json
      end

      # ajax_call :get, '/oauth_back/me' do
      #   access_token = request.cookies['token']
      #   token = JWT.decode access_token, '', false, algorithm: 'RS256'
      #   # user_groups = @kc.user_groups(KC_REALM, token[0]['sub'])
      #   token[0]
      # end

      get('/oauth_back/login') do
        slim :login, layout: false
      end

      ajax_call :post, '/oauth_back/login' do |payload|
        halt 401 unless get_token payload
      end

      ajax_call :get, '/oauth_back/refresh' do |payload|
        halt 401 unless refresh
      end

      get('/oauth_back/logout') do
        logout
        redirect '/oauth_back/login'
      end
    end
  end
end
