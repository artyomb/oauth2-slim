module OpenIDConnect
  def self.included(base)
    base.class_eval do

      # may work with omniauth-openid-connect gem
      get '/.well-known/openid-configuration' do
        proto = env['HTTP_X_FORWARDED_SCHEME'] || env['HTTP_X_FORWARDED_PROTO'] || (request.host =~ /localhost/ ? 'http' : 'https')
        x_path_prefix = env['HTTP_X_FORWARDED_PATH_PREFIX'] || ''
        host = request.host_with_port + ENV['PATH_PREFIX'].to_s + x_path_prefix
        issuer = ENV['OIDC_ISSUER'].to_s.sub(%r{/\z}, '')
        issuer = "#{proto}://#{host}" if issuer.empty?

        content_type :json
        {
          issuer:,
          authorization_endpoint: "#{issuer}/authorize",
          token_endpoint: "#{issuer}/token",
          userinfo_endpoint: "#{issuer}/user",
          end_session_endpoint: "#{issuer}/logout",
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['HS256']
        }.to_json
      end
    end
  end
end
