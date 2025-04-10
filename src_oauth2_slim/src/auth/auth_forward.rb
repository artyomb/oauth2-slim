module AuthForward

  KEY_TEXT = "-----BEGIN RSA PRIVATE KEY-----\n MIIEowIBAAKCAQEA78te1DlUytbaOmSJt2v7jammv1+DYlS3Q+KlJjlKrABxvpYT WTeS/NfuY2tq3OBe/9BuEB2WS5laEJWpQV4ypEhN5agFgTPRNTmErY75adqWsf3t ISKzLTeIdjCgM1BXlkcykJA44Wi++KOsy90ZC6K+tkzRiCFac6eMuXK+zmc6U+6k Sz1uivJ17HABybzi9dVodsObRPJX4ymP85NMgTGNPM0KSKWrC5S1LvOFIHBfID4D C0tqj/5po/g8c50wpAT9yL/+qjkDLs1u0rnCKJAjwhWVSa2Wh2ZFKDk62TDm73JI QwxGzqqxWUGfKCg8JgcS6EQYu952hHYcsQdXoQIDAQABAoIBADjnhcwug77z8Ash 3yWKKEK0owewkpTj3i6rqv3QZDY/j76GzjYikEzUsDNjIxOh4iFqVKgZ4Vf03xDm 9yi2QiXGq8enUREZWxj6mo/2SR1T3GWGSP7PRX5iOo2zmdy7gOF+aVMxinIBYapO 6xtgz0f52bCYt7OKmLSv6t76SingEzk9FGTlCtCaKMyoHEA8qC+WKNqTEndh2DOn oMGX0zPWTmN/9P+epBGAxRVpYkmtCVQlY4u85zteuxs8SWSnkhbwwCazzapqOqKe f/lr/KJiFZ42ta6Zzh4zUvqvA2S8IrP33wm86x7ZyaBhJ8buVKEkZ4Fm5RdEPun4 Uo+Rm+0CgYEA9/dmzwdWfMmGRJoc3rdDJelbVhQeJ8eGNlOnvs4KEUK+HITEzf+u 7F3PohRF8HmgguQKuX6exLkCME9/mAomAqivitrB5aH93ubMjYzleFbwvZRLQgA7 zitdAwdoLKdw2RTo1JQtnw+I+dFDiUyolPANtGlQRJPsk56C+gBekAUCgYEA95Ax Al0byJ9Fdl91LM2MUdc3hLAzqpFnlA6DELnwkx7axshMPh5+O7+cmLMskCDIuXrI w2KNbkKSlpJituxFR37eiSgKsT13amf1pOA35iTA5pAWf6jgD6zWmhK599c/xwFe 1txa9tgCZZVSLRT7RpQ/bFWScY7puRWsaW+CZ+0CgYBkM4pM8KcnZ/wk7q3p5d5x jHoHL7v70SnP/EAV34a78N+IALLSl5alF0eXNGAKy+tr2SDoUl1wG17iDM3/r2Iq wuWk0790vuAq2dMhBCWaWm+P/EPpGNUR+/3rAmw7VzJH1qY7eOFynEF6yfBjpCGf hd3T4Ja6D5iTEoPU6J9NzQKBgQD2SF5ZSaOQTNLf1ktNzRchfAfhWyGrOIhgxKcj BrgMxI9FXpJq4g8XBaKWTvmwUM0fqMT9i5fD7zrBzNOjwx2Q6OgebtVkSg/4rX+1 DNLPhBTbytB3I9vz/DBqiuKza1IpenWNLx7Xn0GTKZ/c9ZidOHJ4JhFQI6rk1Gj3 Y1XKaQKBgB2GSNS5kkAQra12wZbmKSH61yzIxWtv58txy31iTguhSsQy6HaFvBFZ sRU0N3JOGqm8djALzJy/4nNmBoeOUWLy7a16w5qH5ED5CWGL7mtWsZ5+Sn+G9ECB XaWMJ1SovPLMiNg7dxlWuWQbXRI26bN5BBZVkAdUl0ps1KBDeogM\n-----END RSA PRIVATE KEY-----"
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(KEY_TEXT)
  PUBLIC_KEY = PRIVATE_KEY.public_key
  FORWARD_OAUTH_AUTH_URL = ENV['FORWARD_OAUTH_AUTH_URL']
  FORWARD_OAUTH_TOKEN_URL = ENV['FORWARD_OAUTH_TOKEN_URL']
  
  def self.included(base)
    base.class_eval do

      get '/auth' do
        token = request.cookies['auth_token']
        # token = request.env['HTTP_X_AUTH_TOKEN']
        if valid_token?(token)
          # response.headers['X-Auth-Token'] = token
          status 200
          "OK"
        else
          proto = request.env['HTTP_X_FORWARDED_PROTO']
          host = request.env['HTTP_X_FORWARDED_HOST']
          path = request.env['HTTP_X_FORWARDED_URI']
          full_uri = "#{proto}://#{host}#{path}"

          redirect "#{FORWARD_OAUTH_AUTH_URL}?client_id=your-client-id&redirect_uri=#{FORWARD_OAUTH_TOKEN_URL}&response_type=code&scope=openid+profile+email&state=#{URI.encode_www_form_component(full_uri)}", 302
        end
      end

      get '/_oauth' do
        code = params[:code]
        state = params[:state]

        access_token = JWT.encode({
          'iss': "#{FORWARD_OAUTH_AUTH_URL}",
          'sub': 'admin',
          'login': 'admin',
          'role': 'Admin',
          'exp': Time.now.to_i + 3600,
          'iat': Time.now.to_i
        }, PRIVATE_KEY, 'RS256')

        state_uri = URI.parse(state)
        cookie_domain = state_uri.host
        # response.headers['X-Auth-Token'] = access_token
        response.set_cookie('auth_token', value: access_token, path: '/', expires: Time.now + 3600, httponly: true, secure: true, same_site: :none)

        redirect state
      end

      get '/authorize' do
        redirect_uri = params[:redirect_uri]
        state = params[:state]
        client_id = params[:client_id]

        authorization_code = SecureRandom.hex(16)

        redirect "#{redirect_uri}?code=#{authorization_code}&state=#{state}"
      end

      private

      def valid_token?(token)
        if token && !token.empty?
          puts "Token received and is present: #{token}"
          true
        else
          puts "Token is missing or empty"
          false
        end
      end

    end
  end
end