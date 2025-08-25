module OpenIDConnect
  def self.included(base)
    base.class_eval do

      # may work with omniauth-openid-connect gem
      get '/.well-known/openid-configuration' do
        proto = env['HTTP_X_FORWARDED_SCHEME'] || env['HTTP_X_FORWARDED_PROTO'] || (request.host =~ /localhost/ ? 'http' : 'https')
        x_path_prefix = env['HTTP_X_FORWARDED_PATH_PREFIX'] || ''
        host = request.host_with_port + ENV['PATH_PREFIX'].to_s + x_path_prefix
        uri = "#{proto}://#{host}"

        content_type :json
        {
          issuer: "#{uri}/realms/myrealm",
          authorization_endpoint: "#{uri}/openid-connect/auth", # login redirect
          token_endpoint: "#{uri}/openid-connect/token", # exchange code for tokens
          userinfo_endpoint: "#{uri}/openid-connect/userinfo", # fetch user info
          jwks_uri: "#{uri}/openid-connect/certs" # verify ID token signature
        }.to_json
      end
    end
  end
end