require_relative 'ajax'

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

      # get '/authorize' do
      #   #     response_type=code&
      #   #     client_id=portainer_client_id&
      #   #     redirect_uri=http://redirect.com&
      #   #     scope=id,email,name&
      #   #     state=168f5cba-b631-479e-9ff8-a6cbd467a188
      #   r_uri = URI.parse params[:redirect_uri]
      #   redirect = request.referer.to_s + r_uri.path[1..].to_s
      #   redirect "#{redirect}/?code={authorization_code}&state=#{params[:state]}"
      # end

      # request_body = "code=%7Bauthorization_code%7D&grant_type=authorization_code"
      # request_headers.HTTP_AUTHORIZATION ="Basic cG9ydGFpbmVyX2NsaWVudF9pZDpwb3J0YWluZXJfc2VjcmV0"

      # request_body "client_id=portainer_client_id&
      # client_secret=portainer_secret&
      # code=%7Bauthorization_code%7D&
      # grant_type=authorization_code"
      post %r{.*/token_old} do
        # grant_type = request.form.get('grant_type')
        # client_id = request.form.get('client_id')
        # client_secret = request.form.get('client_secret')
        # code = request.form.get('code')
        $stdout.puts "=== POST /token Environment ==="
        request.env.each { |k, v| $stdout.puts "#{k}: #{v}" }
        $stdout.puts "POST params: #{params.inspect}"
        $stdout.puts "Request body: #{request.body.read}"
        request.body.rewind # Сбросить указатель
        $stdout.puts "=========================="
        p (request.form_hash rescue { form_hash: false })

        client_id = 1
        payload = {
          'iss': 'https://your-domain.com',  # Issuer
          'sub': 'admin',  # Subject (user ID) - would typically come from authorization
          'login': 'admin',  # for grafana?
          'role': 'admin',  # for grafana?
          # 'username': 'admin',  # for grafana?
          # 'aud': client_id,  # Audience (client ID)
          'exp': Time.now.to_i + 3600,  # Expiration (1 hour from now)
          'iat': Time.now.to_i,  # Issued at
          # 'jti': 'Unique token ID',  # Unique token ID
          # 'scope': 'id,email,name'  # Authorized scopes
        }
        # @public_key ||= OpenSSL::PKey::RSA.new %(-----BEGIN PUBLIC KEY-----\n#{@realm_info['public_key']}\n-----END PUBLIC KEY-----)
        # new_key = OpenSSL::PKey::RSA.new(2048)
        # key_text = new_key.to_pem
        key_text = "-----BEGIN RSA PRIVATE KEY-----\n MIIEowIBAAKCAQEA78te1DlUytbaOmSJt2v7jammv1+DYlS3Q+KlJjlKrABxvpYT WTeS/NfuY2tq3OBe/9BuEB2WS5laEJWpQV4ypEhN5agFgTPRNTmErY75adqWsf3t ISKzLTeIdjCgM1BXlkcykJA44Wi++KOsy90ZC6K+tkzRiCFac6eMuXK+zmc6U+6k Sz1uivJ17HABybzi9dVodsObRPJX4ymP85NMgTGNPM0KSKWrC5S1LvOFIHBfID4D C0tqj/5po/g8c50wpAT9yL/+qjkDLs1u0rnCKJAjwhWVSa2Wh2ZFKDk62TDm73JI QwxGzqqxWUGfKCg8JgcS6EQYu952hHYcsQdXoQIDAQABAoIBADjnhcwug77z8Ash 3yWKKEK0owewkpTj3i6rqv3QZDY/j76GzjYikEzUsDNjIxOh4iFqVKgZ4Vf03xDm 9yi2QiXGq8enUREZWxj6mo/2SR1T3GWGSP7PRX5iOo2zmdy7gOF+aVMxinIBYapO 6xtgz0f52bCYt7OKmLSv6t76SingEzk9FGTlCtCaKMyoHEA8qC+WKNqTEndh2DOn oMGX0zPWTmN/9P+epBGAxRVpYkmtCVQlY4u85zteuxs8SWSnkhbwwCazzapqOqKe f/lr/KJiFZ42ta6Zzh4zUvqvA2S8IrP33wm86x7ZyaBhJ8buVKEkZ4Fm5RdEPun4 Uo+Rm+0CgYEA9/dmzwdWfMmGRJoc3rdDJelbVhQeJ8eGNlOnvs4KEUK+HITEzf+u 7F3PohRF8HmgguQKuX6exLkCME9/mAomAqivitrB5aH93ubMjYzleFbwvZRLQgA7 zitdAwdoLKdw2RTo1JQtnw+I+dFDiUyolPANtGlQRJPsk56C+gBekAUCgYEA95Ax Al0byJ9Fdl91LM2MUdc3hLAzqpFnlA6DELnwkx7axshMPh5+O7+cmLMskCDIuXrI w2KNbkKSlpJituxFR37eiSgKsT13amf1pOA35iTA5pAWf6jgD6zWmhK599c/xwFe 1txa9tgCZZVSLRT7RpQ/bFWScY7puRWsaW+CZ+0CgYBkM4pM8KcnZ/wk7q3p5d5x jHoHL7v70SnP/EAV34a78N+IALLSl5alF0eXNGAKy+tr2SDoUl1wG17iDM3/r2Iq wuWk0790vuAq2dMhBCWaWm+P/EPpGNUR+/3rAmw7VzJH1qY7eOFynEF6yfBjpCGf hd3T4Ja6D5iTEoPU6J9NzQKBgQD2SF5ZSaOQTNLf1ktNzRchfAfhWyGrOIhgxKcj BrgMxI9FXpJq4g8XBaKWTvmwUM0fqMT9i5fD7zrBzNOjwx2Q6OgebtVkSg/4rX+1 DNLPhBTbytB3I9vz/DBqiuKza1IpenWNLx7Xn0GTKZ/c9ZidOHJ4JhFQI6rk1Gj3 Y1XKaQKBgB2GSNS5kkAQra12wZbmKSH61yzIxWtv58txy31iTguhSsQy6HaFvBFZ sRU0N3JOGqm8djALzJy/4nNmBoeOUWLy7a16w5qH5ED5CWGL7mtWsZ5+Sn+G9ECB XaWMJ1SovPLMiNg7dxlWuWQbXRI26bN5BBZVkAdUl0ps1KBDeogM\n-----END RSA PRIVATE KEY-----"
        private_key = OpenSSL::PKey::RSA.new key_text

        content_type :json
        {
          "access_token": JWT.encode(payload, private_key, 'RS256'),
          'token_type': 'Bearer',
          "token_format": "jwt",
          "token_algorithm": "RS256",
          'expires_in': 3600,
          'refresh_token': 'refresh_token',
          'scope': 'allowed_scopes'
        }.to_json
      end

      post %r{.*/token} do
        # grant_type = request.form.get('grant_type')
        # client_id = request.form.get('client_id')
        # client_secret = request.form.get('client_secret')
        code = request.form.get('code')
        raise 'Invalid code' if code.to_s.empty?
        raise 'Code not found' unless AuthForward::AUTH_CODES.key? code

        attributes = AuthForward::AUTH_CODES[code].slice(:scope, :login)
        access_token = generate_token attributes.merge(email: "#{attributes[:login]}@local.net")
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

      # https://connect2id.com/products/server/docs/api/userinfo
      get %r{.*/user} do
        $stdout.puts "=== USER Request ==="
        request.env.each do |key, value|
          $stdout.puts "#{key}: #{value}"
        end

        # request_headers.HTTP_AUTHORIZATION = "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3lvdXItZG9tYWluLmNvbSIsInN1YiI6ImFkbWluIiwiYXVkIjoxLCJleHAiOjE3MzQyMTk2OTksImlhdCI6MTczNDIxNjA5OSwianRpIjoiVW5pcXVlIHRva2VuIElEIiwic2NvcGUiOiJhbGxvd2VkX3Njb3BlcyJ9.3IJtY4EaQ0lkxtKiEtKp7piZMRjgWmHbaRKDp9Ny78tLN4q7CY13laJ_btoTBEat21lse1LWenc_ZRNuR7AzXXvX5jn04tfXpzth7NejfFCIA3UtIpAoWG_suPFzs9E3950f_QzO9hwcu0xaYTezKhk_s9CC6_2nPnX2DuBw8F3GIM5jCCrvyc4dWP_Guz64aUWDN6R9c8VyEUSWF6LdNB50peLHhc_gWDknqZef-dmC7jB0LKs0lpCvWlcirbDEgaKvVZ3H5q8UpsPGy-ds5XD284sateHetU9MPfV4ZcasCPP8UnejjC0R5gLyCrx7ulfN6tyT5tSvev0a836uew"
        begin
          token = request.env["HTTP_AUTHORIZATION"][/Bearer (.*)/, 1]
          puts "token: #{token}"
          access_token = JWT.decode token, '', false, algorithm: 'RS256'
          p access_token
        rescue => e
          $stderr.puts e.message
          $stderr.puts e.backtrace.join("\n")
        end
        content_type :json
        # OR Content-Type: application/jwt
        response = {
          # sub: "admin",
          # id: 'admin',
          login: access_token['login'],  # for grafana?
          role: 'admin',  # for grafana?
          # username: 'admin',  # for grafana?
          # name: 'admin',
          email: access_token['email'],
          # birthdate: "1975-12-31",
          # "https://claims.example.com/department": "engineering",
          # picture: "https://example.com/83692/photo.jpg"
        }.to_json
        $stdout.puts "response: #{response}"

        response
      end

      get '/logout' do
        # redirect "#{request.referer || 'redirect.fake'}"
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