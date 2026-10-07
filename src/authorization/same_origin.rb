# frozen_string_literal: true

module Authorization
  # StackServiceBase otherwise reflects every Origin with credentialed CORS.
  class SameOrigin
    def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, body = @app.call(env)
      if env['PATH_INFO'].match?(%r{\A/(?:admin/policies|api/v1/(?:me/policies|admin/(?:policies|policy-users)))(?:/|\z)})
        headers = headers.reject { |key, _| key.downcase.start_with?('access-control-') }
        headers['cache-control'] = 'no-store'
      end
      [status, headers, body]
    end
  end
end
