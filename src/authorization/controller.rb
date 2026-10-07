# frozen_string_literal: true

require 'securerandom'
require 'rack/utils'
require_relative 'resolver'
require_relative 'schema'

module Authorization
  module PolicyController
    API_PATH = '/api/v1/admin/policies'
    ADMIN_PATH = File.join(File.dirname(ENV.fetch('DB_USER_ADMIN_PATH', '/admin/users')), 'policies')

    def self.included(base)
      base.class_eval do
        set :policy_repository, nil unless respond_to?(:policy_repository)

        helpers do
          def get_token
            @policy_access_token || super
          end

          def policy_repository
            settings.policy_repository || raise(Error.new('Policy management requires USERS_DB_URL database mode', status: 503, code: 'unavailable'))
          end

          def policy_json(data, status: 200)
            content_type :json
            cache_control :no_store
            halt status, JSON.generate(data)
          end

          def policy_action
            cache_control :no_store
            yield
          rescue Authorization::Error => e
            policy_json({ error: e.message, code: e.code, fields: e.fields, current_revision: e.current_revision }.compact, status: e.status)
          rescue Sequel::DatabaseError => e
            LOGGER.error "Policy database operation failed: #{e.class}"
            policy_json({ error: 'Policy storage is unavailable', code: 'storage_failure' }, status: 503)
          end

          def policy_principal!(admin: false)
            policy_repository
            authorization = request.env['HTTP_AUTHORIZATION'].to_s
            @policy_bearer = !authorization.empty?
            token = @policy_bearer ? authorization[/\ABearer\s+(\S+)\z/i, 1] : get_token
            raise Authorization::Error.new('Authentication required', status: 401, code: 'unauthenticated') if token.to_s.empty?
            @policy_access_token = token

            begin
              @policy_user = authenticated_db_user(token) do |claims|
                issuer = ENV['OIDC_ISSUER'].to_s
                issuer = ENV['FORWARD_OAUTH_AUTH_URL'].to_s if issuer.empty?
                issuer = issuer.sub(%r{/\z}, '')
                audience = ENV.fetch('POLICY_API_AUDIENCE', issuer)
                valid = !issuer.empty? && claims['iss'] == issuer && !claims['sub'].nil?
                valid &&= !claims.key?('aud') || Array(claims['aud']).include?(audience)
                raise JWT::DecodeError, 'Invalid token subject, issuer, or audience' unless valid
              end
            rescue DBUserAuth::RevocationCheckError => e
              raise Authorization::Error.new(e.message, status: 503, code: 'authentication_unavailable')
            end
            if admin && @policy_user[:role] != 'admin'
              raise Authorization::Error.new('Admin role required', status: 403, code: 'forbidden')
            end
            @policy_user
          rescue JWT::DecodeError
            raise Authorization::Error.new('Invalid access token', status: 401, code: 'unauthenticated')
          end

          def policy_csrf_token
            session[:policy_csrf] ||= SecureRandom.hex(32)
          end

          def policy_csrf!
            return if @policy_bearer

            supplied = request.env['HTTP_X_CSRF_TOKEN'].to_s
            expected = session[:policy_csrf].to_s
            unless !expected.empty? && Rack::Utils.secure_compare(expected, supplied)
              raise Authorization::Error.new('CSRF token required; reload the page and retry', status: 403, code: 'csrf_failed')
            end
          end

          def policy_body
            unless request.media_type == 'application/json'
              raise Authorization::Error.new('Content-Type must be application/json', status: 415, code: 'invalid_input')
            end
            body = request.body.read(Authorization::Validation.max_bytes + 1)
            if body.bytesize > Authorization::Validation.max_bytes
              raise Authorization::Error.new('Policy payload is too large', status: 413, code: 'invalid_input')
            end
            data = JSON.parse(body, max_nesting: Authorization::Validation.max_depth + 4)
            raise Authorization::Error.new('Expected a JSON object', status: 400) unless data.is_a?(Hash)

            data
          rescue JSON::ParserError
            raise Authorization::Error.new('Invalid JSON or nesting limit exceeded', status: 400, fields: { definition: 'Invalid JSON or excessive nesting' })
          end

          def policy_audit(event, policy_id:, user_id: nil)
            LOGGER.info JSON.generate(event: "policy.#{event}", actor_id: @policy_user[:id], policy_id:, user_id:)
          end

          def policy_admin_request(write: false)
            policy_action do
              policy_principal!(admin: true)
              policy_csrf! if write
              yield
            end
          end

          def policy_path
            "#{request.script_name}#{Authorization::PolicyController::ADMIN_PATH}"
          end
        end

        get ADMIN_PATH do
          cache_control :no_store
          unless settings.policy_repository
            status 503
            next slim(:policies_unavailable)
          end
          policy_action do
            if params[:code]
              grant = consume_authorization_code(params[:code])
              raise Authorization::Error.new('Authorization code not found', status: 401, code: 'unauthenticated') unless grant

              generate_token(authorization_code_identity(grant).merge(scope: grant[:scope]))
              redirect policy_path
            end
            unless get_token
              query = URI.encode_www_form(redirect_uri: "#{request.base_url}#{policy_path}", response_type: 'code', scope: ENV['AUTH_SCOPE'] || request.host)
              redirect "#{ENV.fetch('FORWARD_OAUTH_AUTH_URL')}?#{query}"
            end
            policy_principal!(admin: true)
            slim :policies_admin
          end
        end

        %w[css/policies.css js/policy-json.js js/policies.js].each do |asset|
          get "#{ADMIN_PATH}/#{asset}" do
            send_file File.expand_path("../public/#{asset}", __dir__)
          end
        end

        get '/api/v1/me/policies' do
          policy_action do
            subject = policy_principal!
            unless (params.keys - %w[resource_type action]).empty?
              raise Authorization::Error.new('Only resource_type and action selectors are accepted', status: 400)
            end
            resolver = Authorization::PolicyResolver.new(policy_repository)
            policy_json(resolver.resolve(subject[:id], resource_type: params['resource_type'], action: params['action']))
          end
        end

        ['/api/v1/admin/policy-users', "#{ADMIN_PATH}/users"].each do |path|
          get path do
            policy_admin_request { policy_json(policy_repository.users(params)) }
          end
        end

        [API_PATH, "#{ADMIN_PATH}/data"].each do |api_path|
          get api_path do
            policy_admin_request { policy_json(policy_repository.list(params)) }
          end

          post api_path do
            policy_admin_request(write: true) do
              policy = policy_repository.create(Authorization::Validation.policy(policy_body))
              policy_audit('created', policy_id: policy[:id])
              headers['Location'] = "#{request.script_name}#{api_path}/#{policy[:id]}"
              policy_json(policy, status: 201)
            end
          end

          get "#{api_path}/:id" do
            policy_admin_request { policy_json(policy_repository.find(Authorization::Validation.id(params[:id]))) }
          end

          patch "#{api_path}/:id" do
            policy_admin_request(write: true) do
              input = policy_body
              revision = Authorization::Validation.revision(input)
              attributes = Authorization::Validation.policy(input, partial: true)
              policy = policy_repository.update(Authorization::Validation.id(params[:id]), attributes, expected_revision: revision)
              policy_audit('updated', policy_id: policy[:id])
              policy_json(policy)
            end
          end

          delete "#{api_path}/:id" do
            policy_admin_request(write: true) do
              revision = Authorization::Validation.revision(policy_body)
              id = Authorization::Validation.id(params[:id])
              policy_repository.delete(id, expected_revision: revision)
              policy_audit('deleted', policy_id: id)
              policy_json({ notice: 'Policy deleted' })
            end
          end

          get "#{api_path}/:id/assignments" do
            policy_admin_request { policy_json(policy_repository.assignments(Authorization::Validation.id(params[:id]), params)) }
          end

          put "#{api_path}/:id/assignments/users/:user_id" do
            policy_admin_request(write: true) do
              id, user_id = %i[id user_id].map { |key| Authorization::Validation.id(params[key]) }
              policy_repository.assign(id, user_id)
              policy_audit('assigned', policy_id: id, user_id:)
              policy_json({ notice: 'Policy assigned' })
            end
          end

          delete "#{api_path}/:id/assignments/users/:user_id" do
            policy_admin_request(write: true) do
              id, user_id = %i[id user_id].map { |key| Authorization::Validation.id(params[key]) }
              policy_repository.assign(id, user_id, remove: true)
              policy_audit('unassigned', policy_id: id, user_id:)
              policy_json({ notice: 'Assignment removed' })
            end
          end
        end
      end
    end
  end
end
