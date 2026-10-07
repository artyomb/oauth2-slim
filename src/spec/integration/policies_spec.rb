# frozen_string_literal: true

require_relative '../spec_helper'

if ENV['POLICY_TEST_DATABASE_URL'].to_s.empty?
  RSpec.describe('PostgreSQL policy integration') do
    it('requires a disposable database') { skip 'Set POLICY_TEST_DATABASE_URL to a disposable PostgreSQL database ending in _test' }
  end
else
  require 'json'
  require 'logger'
  require 'rack/mock'
  require 'sinatra/base'
  require 'slim'
  require 'uri'
  require 'open3'

  test_url = ENV.fetch('POLICY_TEST_DATABASE_URL')
  raise 'POLICY_TEST_DATABASE_URL database name must end in _test' unless URI.parse(test_url).path.end_with?('_test')

  ENV['RACK_ENV'] = 'test'
  ENV['FORWARD_OAUTH_AUTH_URL'] = '/authorize'
  ENV['OIDC_ISSUER'] = 'https://auth.test'
  ENV['DB_USER_SEED'] = 'false'
  LOGGER = Logger.new(File::NULL) unless defined?(LOGGER)
  ENV['USERS_DB_URL'] = test_url
  require_relative '../../auth/db_user_auth'
  ENV.delete('USERS_DB_URL')
  require_relative '../../auth/token'
  require_relative '../../auth/auth20'
  require_relative '../../authorization/controller'
  require_relative '../../i18n_setup'
  FORWARD_AUTH = {} unless defined?(FORWARD_AUTH)

  class PolicyIntegrationApp < Sinatra::Base
    set :environment, :test
    set :raise_errors, true
    set :show_exceptions, false
    set :sessions, { secret: 'policy-integration-secret-' * 4 }
    set :views, File.expand_path('../../views', __dir__)
    set :policy_repository, Authorization::PolicyRepository.new(DB)
    helpers Token, AuthorizationCode, Auth20, DBUserAuth, Authorization::PolicyController
    helpers do
      def t(key, **options) = I18n.t(key, **options)
      def valid_redirect_uri!(value) = URI.parse(value)
    end
  end

  class UnavailablePolicyApp < Sinatra::Base
    set :environment, :test
    set :views, File.expand_path('../../views', __dir__)
    helpers Authorization::PolicyController
    helpers do
      def t(key, **options) = I18n.t(key, **options)
    end
  end

  RSpec.describe 'PostgreSQL policy integration' do
    let(:request) { Rack::MockRequest.new(PolicyIntegrationApp) }
    let(:repository) { PolicyIntegrationApp.policy_repository }
    let(:api) { '/api/v1/admin/policies' }
    let(:admin_path) { Authorization::PolicyController::ADMIN_PATH }
    let(:runtime) { '/api/v1/me/policies?resource_type=resource&action=read' }
    let(:definition) do
      { 'example' => { 'values' => ['Юникод'] },
        'groups_conditions' => [{ 'AND' => [{ 'not' => { 'not' => { 'value' => 1.25 } } }] }],
        'matrices' => [[{ 'values' => [[[37.625, 55.75], [38, 54], [37.625, 55.75]]], 'optional' => nil }]],
        'integer' => 9_007_199_254_740_993 }
    end
    let(:attributes) do
      { 'name' => 'Test policy', 'type' => 'filter', 'resource_type' => 'resource',
        'actions' => ['read'], 'effect' => 'allow', 'definition' => definition }
    end

    before do
      DB[:user_policies].delete
      DB[:authorization_policies].delete
      DB[:oauth_users].delete
      @admin = DB[:oauth_users].insert(login: 'admin', role: 'admin', password_hash: 'unused')
      @alice = DB[:oauth_users].insert(login: 'alice', name: 'Alice', password_hash: 'unused')
      @bob = DB[:oauth_users].insert(login: 'bob', password_hash: 'unused')
      @revoked = FORWARD_AUTH[:revoked?]
      FORWARD_AUTH[:revoked?] = -> { false }
      ENV['OIDC_ISSUER'] = 'https://auth.test'
    end

    after { FORWARD_AUTH[:revoked?] = @revoked }

    def token(id, extra = {})
      JWT.encode({ sub: id.to_s, uid: id, iss: 'https://auth.test', exp: Time.now.to_i + 3600, role: id == @admin ? 'admin' : '', login: id == @admin ? 'admin' : 'alice', **extra }, SIGNING_KEY, 'EdDSA')
    end

    def call(method, path, data = nil, as: @admin, headers: {})
      options = { 'CONTENT_TYPE' => 'application/json', **headers }
      options['HTTP_AUTHORIZATION'] = "Bearer #{token(as)}" if as
      options[:input] = JSON.generate(data) if data
      request.request(method, path, options)
    end

    def body(response) = JSON.parse(response.body)

    def create(overrides = {})
      response = call('POST', api, attributes.merge(overrides))
      expect(response.status).to eq(201), response.body
      body(response)
    end

    def effective = body(call('GET', runtime, as: @alice))

    it 'creates disabled policies and round trips nested JSON, numbers, Unicode, arrays, and nulls' do
      policy = create
      expect(policy).to include('active' => false, 'revision' => 1, 'schema_version' => 1, 'definition' => definition)
      expect(body(call('GET', "#{api}/#{policy['id']}"))['definition']).to eq(definition)
    end

    it 'persists policies and bindings across a fresh process and repeated migrations' do
      policy = create
      repository.assign(policy['id'], @alice)
      script = <<~RUBY
        require_relative 'auth/db_user_auth'
        require_relative 'authorization/repository'
        repository = Authorization::PolicyRepository.new(DB)
        puts JSON.generate(policy: repository.find(#{policy['id']}), count: DB[:user_policies].where(policy_id: #{policy['id']}).count)
      RUBY
      output, error, status = Open3.capture3({ 'USERS_DB_URL' => ENV.fetch('POLICY_TEST_DATABASE_URL'), 'DB_USER_SEED' => 'false' }, 'bundle', 'exec', 'ruby', '-e', script, chdir: File.expand_path('../..', __dir__))
      expect(status.success?).to be(true), error
      expect(JSON.parse(output)).to include('count' => 1)
      expect(JSON.parse(output)['policy']['definition']).to eq(definition)
    end

    it 'migrates an existing populated user database without assigning access' do
      before_users = DB[:oauth_users].all
      Authorization::Schema.migrate(DB)
      expect(DB[:oauth_users].all).to eq(before_users)
      expect(DB[:user_policies].count).to eq(0)
    end

    it 'creates the policy schema on an installation with only the existing users table' do
      schema = "policy_migration_#{SecureRandom.hex(6)}"
      DB.create_schema(schema)
      isolated = Sequel.connect(ENV.fetch('POLICY_TEST_DATABASE_URL'), search_path: schema)
      isolated.create_table(:oauth_users) { primary_key :id; String :login }
      isolated[:oauth_users].insert(login: 'existing-user')
      Authorization::Schema.migrate(isolated)
      expect(isolated[:authorization_policies].count).to eq(0)
      expect(isolated[:user_policies].count).to eq(0)
      expect(isolated[:oauth_users].get(:login)).to eq('existing-user')
      Authorization::Schema.migrate(isolated)
      expect(isolated[:authorization_schema_info].get(:version)).to eq(1)
    ensure
      isolated&.disconnect
      DB.drop_schema(schema, cascade: true) if schema
    end

    it 'rejects invalid API payloads before writing records' do
      [{ 'definition' => [] }, { 'effect' => 'unknown' }, { 'schema_version' => 2 }, { 'actions' => [] }].each do |changes|
        expect(call('POST', api, attributes.merge(changes)).status).to eq(422)
      end
      expect(call('POST', api, attributes.merge('definition' => { 'huge' => 'x' * Authorization::Validation.max_bytes })).status).to eq(413)
      malformed = request.post(api, 'HTTP_AUTHORIZATION' => "Bearer #{token(@admin)}", 'CONTENT_TYPE' => 'application/json', input: '{broken')
      expect(malformed.status).to eq(400)
      expect(DB[:authorization_policies].count).to eq(0)
    end

    it 'rejects unauthorized reads, writes, and assignments, including a demoted administrator' do
      policy = create
      [['GET', api], ['POST', api], ['PATCH', "#{api}/#{policy['id']}"], ['DELETE', "#{api}/#{policy['id']}"], ['GET', "#{api}/#{policy['id']}/assignments"], ['PUT', "#{api}/#{policy['id']}/assignments/users/#{@bob}"], ['DELETE', "#{api}/#{policy['id']}/assignments/users/#{@bob}"], ['GET', '/api/v1/admin/policy-users']].each do |method, path|
        expect(call(method, path, as: nil).status).to eq(401)
        expect(call(method, path, as: @alice).status).to eq(403)
      end
      old_token = token(@admin)
      DB[:oauth_users].where(id: @admin).update(role: 'user')
      expect(call('GET', api, as: nil, headers: { 'HTTP_AUTHORIZATION' => "Bearer #{old_token}" }).status).to eq(403)
    end

    it 'rejects expired, revoked, wrong issuer/audience, malformed, or inconsistent tokens' do
      [{ exp: Time.now.to_i - 1 }, { iss: 'https://other.test' }, { aud: 'other-api' }, { uid: @bob }, { sub: 'alice' }].each do |claims|
        response = call('GET', runtime, as: nil, headers: { 'HTTP_AUTHORIZATION' => "Bearer #{token(@alice, claims)}" })
        expect(response.status).to eq(401)
      end
      expect(call('GET', runtime, as: nil, headers: { 'HTTP_AUTHORIZATION' => 'Bearer invalid' }).status).to eq(401)
      FORWARD_AUTH[:revoked?] = -> { true }
      expect(call('GET', runtime, as: @alice).status).to eq(401)
    end

    it 'fails closed when revocation checking fails' do
      FORWARD_AUTH[:revoked?] = -> { raise 'Unavailable' }
      response = call('GET', runtime, as: @alice)
      expect(response.status).to eq(503)
      expect(body(response)).not_to have_key('data')
    end

    it 'checks revocation against the bearer credential even when another user cookie exists' do
      alice = @alice
      FORWARD_AUTH[:revoked?] = -> { decode_token(get_token)['sub'] == alice.to_s }
      expect(call('GET', runtime, as: @alice).status).to eq(401)
      response = call('GET', runtime, as: @alice, headers: { 'HTTP_COOKIE' => "#{COOKIE_TOKEN_NAME}=#{token(@bob)}" })
      expect(response.status).to eq(401)
      expect(call('GET', runtime, as: @bob).status).to eq(200)
    end

    it 'returns the complete exact matching set beyond the admin page size' do
      28.times do |index|
        policy = create('active' => true, 'name' => "Policy #{index}", 'priority' => index % 2)
        repository.assign(policy['id'], @alice)
      end
      [ { 'active' => false }, { 'active' => true, 'actions' => ['read:extra'] }, { 'active' => true, 'resource_type' => 'resource-extra' } ].each do |changes|
        policy = create(changes)
        repository.assign(policy['id'], @alice)
      end
      create('active' => true)
      expect(body(call('GET', api))['data'].size).to eq(25)
      result = effective
      expect(result).to include('complete' => true, 'subject' => { 'id' => @alice })
      expect(result['data'].size).to eq(28)
      expect(result['data'].map { |policy| [policy['priority'], policy['id']] }).to eq(result['data'].map { |policy| [policy['priority'], policy['id']] }.sort)
      expect(result['data'].first['assigned_via']).to eq([{ 'type' => 'user', 'id' => @alice }])
      expect(call('GET', runtime, as: @alice)['cache-control']).to include('no-store')
    end

    it 'cannot redirect /me to another subject and requires selectors' do
      expect(call('GET', "#{runtime}&user_id=#{@bob}", as: @alice).status).to eq(400)
      expect(call('GET', '/api/v1/me/policies', as: @alice).status).to eq(400)
      expect(body(call('GET', runtime, { user_id: @bob }, as: @alice))['subject']).to eq('id' => @alice)
      expect(effective).to include('complete' => true, 'data' => [])
    end

    it 'changes the set version on edits, state changes, and binding changes' do
      policy = create('active' => true)
      original = effective['policy_set_version']
      repository.assign(policy['id'], @alice)
      assigned = effective['policy_set_version']
      expect(assigned).not_to eq(original)
      expect(effective['policy_set_version']).to eq(assigned)
      repository.update(policy['id'], { description: 'Changed' }, expected_revision: 1)
      edited = effective['policy_set_version']
      expect(edited).not_to eq(assigned)
      repository.update(policy['id'], { active: false }, expected_revision: 2)
      expect(effective['policy_set_version']).to eq(original)
      repository.update(policy['id'], { active: true }, expected_revision: 3)
      repository.assign(policy['id'], @alice, remove: true)
      expect(effective['policy_set_version']).to eq(original)
    end

    it 'replaces definitions atomically and rejects stale edits and deletion' do
      policy = create
      updated = call('PATCH', "#{api}/#{policy['id']}", { expected_revision: 1, definition: { matrices: [] } })
      expect(body(updated)).to include('revision' => 2, 'definition' => { 'matrices' => [] })
      stale = call('PATCH', "#{api}/#{policy['id']}", { expected_revision: 1, name: 'Lost edit' })
      expect(stale.status).to eq(409)
      expect(body(stale)).to include('code' => 'stale_revision', 'current_revision' => 2)
      expect(call('DELETE', "#{api}/#{policy['id']}", { expected_revision: 1 }).status).to eq(409)
      expect(call('PATCH', "#{api}/#{policy['id']}", { name: 'Missing revision' }).status).to eq(400)
    end

    it 'serializes concurrent edits so exactly one succeeds' do
      policy = create
      ready, start = Queue.new, Queue.new
      threads = 2.times.map do |index|
        Thread.new do
          ready << true; start.pop
          repository.update(policy['id'], { name: "Edit #{index}" }, expected_revision: 1)
          :updated
        rescue Authorization::Error => e
          e.code
        end
      end
      2.times { ready.pop }; 2.times { start << true }
      expect(threads.map(&:value)).to contain_exactly(:updated, 'stale_revision')
    end

    it 'blocks deletion of enabled or assigned policies and permits disabled unassigned deletion' do
      policy = create('active' => true)
      path = "#{api}/#{policy['id']}"
      expect(call('DELETE', path, { expected_revision: 1 }).status).to eq(409)
      repository.update(policy['id'], { active: false }, expected_revision: 1)
      repository.assign(policy['id'], @alice)
      expect(call('DELETE', path, { expected_revision: 2 }).status).to eq(409)
      repository.assign(policy['id'], @alice, remove: true)
      expect(call('DELETE', path, { expected_revision: 2 }).status).to eq(200)
      expect(call('GET', path).status).to eq(404)
    end

    it 'does not race policy deletion with a new assignment' do
      policy = create
      ready, start = Queue.new, Queue.new
      threads = [:assign, :delete].map do |operation|
        Thread.new do
          ready << true; start.pop
          operation == :assign ? repository.assign(policy['id'], @alice) : repository.delete(policy['id'], expected_revision: 1)
          operation
        rescue Authorization::Error => e
          e.code
        end
      end
      2.times { ready.pop }; 2.times { start << true }
      result = threads.map(&:value)
      expect(result == [:assign, 'deletion_conflict'] || result == ['not_found', :delete]).to be(true), result.inspect
    end

    it 'keeps one binding under concurrent assignment requests' do
      policy = create
      threads = 4.times.map { Thread.new { repository.assign(policy['id'], @alice) } }
      threads.each(&:value)
      expect(DB[:user_policies].where(policy_id: policy['id'], user_id: @alice).count).to eq(1)
    end

    it 'makes assignment changes idempotent, validates users, and cleans bindings on user deletion' do
      policy = create
      path = "#{api}/#{policy['id']}/assignments/users/#{@alice}"
      2.times { expect(call('PUT', path).status).to eq(200) }
      expect(DB[:user_policies].count).to eq(1)
      expect(call('PUT', "#{api}/#{policy['id']}/assignments/users/2147483647").status).to eq(404)
      2.times { expect(call('DELETE', path).status).to eq(200) }
      expect(DB[:user_policies].count).to eq(0)
      repository.assign(policy['id'], @alice)
      DB[:oauth_users].where(id: @alice).delete
      expect(DB[:user_policies].count).to eq(0)
      expect(call('GET', runtime, as: @alice).status).to eq(401)
    end

    it 'removes bindings to soft-deleted users while rejecting new assignments and authentication' do
      policy = create
      path = "#{api}/#{policy['id']}/assignments/users/#{@alice}"
      expect(call('PUT', path).status).to eq(200)
      DB[:oauth_users].where(id: @alice).update(deleted_at: Time.now.utc)
      expect(call('GET', runtime, as: @alice).status).to eq(401)
      expect(call('PUT', path).status).to eq(404)
      2.times { expect(call('DELETE', path).status).to eq(200) }
      expect(call('DELETE', "#{api}/#{policy['id']}", { expected_revision: 1 }).status).to eq(200)
    end

    it 'returns list metadata and accurate counts with a bounded number of database queries' do
      25.times do |index|
        policy = create('name' => "Policy #{index}")
        repository.assign(policy['id'], @alice) if index.even?
      end
      queries = []
      logger = Object.new
      allow(logger).to receive(:info) { |message| queries << message }
      DB.loggers << logger
      begin
        page = repository.list({})
      ensure
        DB.loggers.delete(logger)
      end
      expect(page[:data].length).to eq(25)
      expect(page[:data].any? { |policy| policy.key?(:definition) }).to be(false)
      expect(page[:data].sum { |policy| policy[:assignment_count] }).to eq(13)
      expect(queries.count { |query| query.include?('SELECT') }).to be <= 3
    end

    it 'never returns success or a partial set when storage fails' do
      allow(repository).to receive(:effective).and_raise(Sequel::DatabaseError, 'private connection data')
      response = call('GET', runtime, as: @alice)
      expect(response.status).to eq(503)
      expect(body(response)).to include('code' => 'storage_failure')
      expect(response.body).not_to include('private connection data', '"data"', '"complete"')
    end

    it 'provides paginated admin search, filters, user lookup, and binding identities' do
      policy = create('name' => 'Policy 100%', 'active' => true)
      create('name' => 'Other')
      repository.assign(policy['id'], @alice)
      expect(body(call('GET', "#{api}?search=100%25&active=true&action=read&resource_type=resource&type=filter"))['total']).to eq(1)
      users = body(call('GET', '/api/v1/admin/policy-users?search=alice&limit=1'))
      expect(users['data']).to eq([{ 'id' => @alice, 'login' => 'alice', 'name' => 'Alice' }])
      bindings = body(call('GET', "#{api}/#{policy['id']}/assignments"))
      expect(bindings['data'].first).to include('id' => @alice, 'type' => 'user', 'login' => 'alice')
    end

    it 'requires CSRF for cookie-authenticated mutations and renders the real admin page' do
      cookie = "#{COOKIE_TOKEN_NAME}=#{token(@admin)}"
      page = call('GET', admin_path, as: nil, headers: { 'HTTP_COOKIE' => cookie })
      expect(page.status).to eq(200), page.body
      expect(page.body).to include('policy-form', 'policy-bindings', 'policy-translations')
      csrf = page.body[/data-csrf="([^"]+)"/, 1]
      session_cookie = Array(page['set-cookie']).find { |value| value.start_with?('rack.session=') }.split(';').first
      headers = { 'HTTP_COOKIE' => "#{cookie}; #{session_cookie}" }
      [api, "#{admin_path}/data"].each do |path|
        expect(call('POST', path, attributes, as: nil, headers:).status).to eq(403)
        expect(call('POST', path, attributes, as: nil, headers: headers.merge('HTTP_X_CSRF_TOKEN' => csrf)).status).to eq(201)
      end
    end

    it 'keeps navigation, assets, and browser APIs beneath the configured policy ingress' do
      cookie = { 'HTTP_COOKIE' => "#{COOKIE_TOKEN_NAME}=#{token(@admin)}" }
      expect(admin_path).to eq(File.join(File.dirname(DB_USER_ADMIN_PATH), 'policies'))
      ['', '/auth-proxy'].each do |mount|
        headers = cookie.merge('SCRIPT_NAME' => mount)
        page = call('GET', admin_path, as: nil, headers:)
        expect(page.status).to eq(200), page.body
        expect(page.body).to include("href=\"#{mount}#{DB_USER_ADMIN_PATH}\"", "data-api=\"#{mount}#{admin_path}/data\"", "data-users-api=\"#{mount}#{admin_path}/users\"")
        users = call('GET', DB_USER_ADMIN_PATH, as: nil, headers:)
        expect(users.status).to eq(200), users.body
        expect(users.body).to include("href=\"#{mount}#{admin_path}\"")
        { 'css/policies.css' => 'text/css', 'js/policy-json.js' => 'javascript', 'js/policies.js' => 'javascript' }.each do |asset, content_type|
          expect(page.body).to include("#{mount}#{admin_path}/#{asset}")
          response = call('GET', "#{admin_path}/#{asset}", as: nil, headers:)
          expect(response.status).to eq(200)
          expect(response['content-type']).to include(content_type)
          expect(response.body).to eq(File.binread(File.expand_path("../../public/#{asset}", __dir__)))
        end
      end
    end

    it 'serves the full protected management workflow under the policy page path' do
      path = "#{admin_path}/data"
      response = call('POST', path, attributes)
      expect(response.status).to eq(201), response.body
      record_path = "#{path}/#{body(response)['id']}"
      expect(response['location']).to eq(record_path)
      expect(body(call('GET', path))['total']).to eq(1)
      expect(body(call('GET', "#{admin_path}/users?search=alice"))['data'].map { |user| user['id'] }).to eq([@alice])
      expect(body(call('PATCH', record_path, { expected_revision: 1, name: 'Updated' }))['revision']).to eq(2)
      assignment = "#{record_path}/assignments/users/#{@alice}"
      expect(call('PUT', assignment).status).to eq(200)
      expect(body(call('GET', "#{record_path}/assignments"))['total']).to eq(1)
      [['GET', path], ['POST', path], ['GET', record_path], ['PATCH', record_path], ['DELETE', record_path],
       ['GET', "#{record_path}/assignments"], ['PUT', assignment], ['DELETE', assignment], ['GET', "#{admin_path}/users"]].each do |method, url|
        expect(call(method, url, as: nil).status).to eq(401)
        expect(call(method, url, as: @alice).status).to eq(403)
      end
      expect(call('DELETE', assignment).status).to eq(200)
      expect(call('DELETE', record_path, { expected_revision: 2 }).status).to eq(200)
      expect(call('GET', record_path).status).to eq(404)
    end

    it 'uses the public policy path as the login return URL behind a proxy' do
      response = call('GET', admin_path, as: nil, headers: { 'HTTP_X_FORWARDED_PROTO' => 'https', 'HTTP_X_FORWARDED_HOST' => 'auth.test', 'SCRIPT_NAME' => '/auth-proxy' })
      expect(response.status).to eq(302)
      query = URI.decode_www_form(URI.parse(response['location']).query).to_h
      expect(query['redirect_uri']).to eq("https://auth.test/auth-proxy#{admin_path}")
    end

    it 'preserves stable database IDs when reusing an existing login cookie' do
      response = call('GET', '/authorize?redirect_uri=https%3A%2F%2Fapp.test%2Fcallback', as: nil, headers: { 'HTTP_COOKIE' => "#{COOKIE_TOKEN_NAME}=#{token(@alice)}" })
      expect(response.status).to eq(302)
      code = URI.decode_www_form(URI.parse(response['location']).query).to_h.fetch('code')
      expect(AUTH_CODES.fetch(code)[:uid]).to eq(@alice)
      exchanged = request.post('/token', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded', input: URI.encode_www_form(code:))
      claims = JWT.decode(body(exchanged)['access_token'], SIGNING_KEY.verify_key, true, algorithm: 'EdDSA').first
      expect(claims).to include('uid' => @alice, 'sub' => @alice.to_s)
    end

    it 'does not let a demoted administrator use the existing user admin to restore privileges' do
      cookie = "#{COOKIE_TOKEN_NAME}=#{token(@admin)}"
      DB[:oauth_users].where(id: @admin).update(role: 'user')
      response = call('GET', DB_USER_ADMIN_PATH, as: nil, headers: { 'HTTP_COOKIE' => cookie })
      expect(response.status).to eq(403)
    end

    it 'shares identity and revocation checks between DB-user sessions and policy authentication' do
      invalid_tokens = [token(@admin, exp: Time.now.to_i - 1), token(@admin, uid: @bob)]
      invalid_tokens.each do |access_token|
        headers = { 'HTTP_COOKIE' => "#{COOKIE_TOKEN_NAME}=#{access_token}" }
        expect(call('GET', DB_USER_ADMIN_PATH, as: nil, headers:).status).to eq(302)
        expect(call('GET', api, as: nil, headers:).status).to eq(401)
      end
      admin_id = @admin
      FORWARD_AUTH[:revoked?] = -> { decode_token(get_token)['sub'] == admin_id.to_s }
      headers = { 'HTTP_COOKIE' => "#{COOKIE_TOKEN_NAME}=#{token(@admin)}" }
      expect(call('GET', DB_USER_ADMIN_PATH, as: nil, headers:).status).to eq(302)
      expect(call('GET', api, as: nil, headers:).status).to eq(401)
      FORWARD_AUTH[:revoked?] = -> { raise 'Unavailable' }
      expect(call('GET', DB_USER_ADMIN_PATH, as: nil, headers:).status).to eq(302)
      expect(call('GET', api, as: nil, headers:).status).to eq(503)
    end

    it 'finishes the admin login callback without requiring an existing cookie' do
      AUTH_CODES['policy-admin-code'] = { uid: @admin, login: 'admin', role: 'admin', time: Time.now.to_i }
      response = call('GET', "#{admin_path}?code=policy-admin-code", as: nil)
      expect(response.status).to eq(302)
      expect(response['location']).to end_with(admin_path)
      expect(Array(response['set-cookie']).join).to include(COOKIE_TOKEN_NAME)
      expect(AUTH_CODES).not_to have_key('policy-admin-code')
    end

    it 'explicitly reports non-DB mode as unavailable and leaves service resolution absent' do
      unavailable = Rack::MockRequest.new(UnavailablePolicyApp)
      expect(unavailable.get('/api/v1/me/policies').status).to eq(503)
      expect(unavailable.get(admin_path).status).to eq(503)
      expect(call('POST', '/api/v1/authorization/resolve', { subject: { id: @alice } }).status).to eq(404)
    end
  end
end
