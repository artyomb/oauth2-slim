# frozen_string_literal: true

module Authorization
  # StackServiceBase otherwise reflects every Origin with credentialed CORS.
  class SameOrigin
    def initialize(app, admin_path: '/admin/policies')
      @app = app
      @paths = [admin_path, '/api/v1/me/policies', '/api/v1/admin/policies', '/api/v1/admin/policy-users']
    end

    def call(env)
      status, headers, body = @app.call(env)
      if @paths.any? { |path| env['PATH_INFO'] == path || env['PATH_INFO'].start_with?("#{path}/") }
        headers = headers.reject { |key, _| key.downcase.start_with?('access-control-') }
        headers['cache-control'] = 'no-store'
      end
      [status, headers, body]
    end
  end
end
