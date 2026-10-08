# frozen_string_literal: true

require_relative '../spec_helper'

if ENV['TRAEFIK_BINARY'].to_s.empty?
  RSpec.describe('Traefik assertion integration') do
    it('requires Traefik 3.6.4') { skip 'Set TRAEFIK_BINARY to a local Traefik 3.6.4 binary' }
  end
else
  require 'base64'
  require 'digest'
  require 'ed25519'
  require 'json'
  require 'jwt'
  require 'jwt/eddsa'
  require 'net/http'
  require 'socket'
  require 'timeout'
  require 'tmpdir'
  require 'yaml'
  require_relative '../../examples/auth_jwt_middleware'

  RSpec.describe 'Traefik assertion integration' do
    def http(port, target, host: 'insight.test', headers: {}, cookie: true, basic: true)
      request = Net::HTTP::Get.new(target)
      request['Host'] = host
      request['Cookie'] = "auth_token=#{@session_token}" if cookie
      request.basic_auth('operator', 'test-password') if basic
      headers.each { |key, value| request[key] = value }
      Net::HTTP.start('127.0.0.1', port, nil, open_timeout: 2, read_timeout: 5) { |client| client.request(request) }
    end

    def spawn_server(file, port, **env)
      child_env = {
        'RACK_ENV' => 'test', 'AUTH_SCOPE' => 'auth.test', 'AUTH_JWT_ENABLED' => 'true',
        'AUTH_VERIFY_KEY' => nil, 'USERS_DB_URL' => nil, 'TELEGRAM_AUTH_BOT' => nil, 'USERS_YAML' => nil,
        'KEY_ENDPOINT' => "http://127.0.0.1:#{@auth_port}/.well-known/auth-jwks.json",
        **env.transform_keys(&:to_s)
      }
      @pids << Process.spawn(child_env, 'bundle', 'exec', 'rackup', file, '-s', 'falcon', '-o', '127.0.0.1', '-p', port.to_s,
                             chdir: @src, out: File.join(@directory, "#{port}.log"), err: [:child, :out])
    end

    def await_response(port, target = '/')
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 20
      loop do
        begin
          response = http(port, target)
          return response if yield(response)
        rescue Errno::ECONNREFUSED, EOFError, Net::ReadTimeout, Errno::ECONNRESET
          nil
        end
        raise "Fixture failed to become ready; inspect #{@directory}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.05
      end
    end

    before(:context) do
      @src = File.expand_path('../..', __dir__)
      @directory = Dir.mktmpdir('oauth-slim-traefik-')
      @pids = []
      sockets = 4.times.map { TCPServer.new('127.0.0.1', 0) }
      @auth_port, @backend_port, @proxy_port, @other_port = sockets.map { |socket| socket.addr[1] }
      sockets.each(&:close)
      auth_file = File.join(@directory, 'auth.ru')
      File.write(auth_file, <<~RUBY)
        require 'logger'
        require 'sinatra/base'
        LOGGER = Logger.new(File::NULL)
        FORWARD_OAUTH_AUTH_URL = '/authorize'
        require #{@src.dump} + '/auth/auth_forward'
        class AssertionFixtureAuth < Sinatra::Base
          set :environment, :test
          set :show_exceptions, false
          helpers AuthForward
          get('/fixture/redirect') { redirect '/.well-known/auth-jwks.json' }
          get('/fixture/oversized') { 'x' * 65_537 }
        end
        run AssertionFixtureAuth
      RUBY
      backend_file = File.join(@directory, 'backend.ru')
      File.write(backend_file, <<~RUBY)
        require 'rack/auth/basic'
        require #{@src.dump} + '/examples/auth_jwt_middleware'
        backend = lambda do |env|
          if env['HTTP_UPGRADE'].to_s.downcase == 'websocket'
            accept = Base64.strict_encode64(Digest::SHA1.digest(env.fetch('HTTP_SEC_WEBSOCKET_KEY') + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'))
            [101, { 'rack.protocol' => 'websocket', 'sec-websocket-accept' => accept }, ->(stream) { stream.close }]
          else
            [200, { 'content-type' => 'application/json' }, [JSON.generate(target: env['REQUEST_URI'], identity: env['oauth_slim.identity'], assertion_present: env.key?('HTTP_X_AUTH_JWT'))]]
          end
        end
        protected_backend = Rack::Auth::Basic.new(backend) { |user, password| user == 'operator' && password == 'test-password' }
        use OAuthSlim::AuthJwtMiddleware, audience: ENV.fetch('AUDIENCE'), key_endpoint: ENV.fetch('KEY_ENDPOINT'),
            authorize: ->(identity, _) { identity['role'] == 'admin' }
        run protected_backend
      RUBY
      spawn_server(auth_file, @auth_port)
      await_response(@auth_port, '/.well-known/auth-jwks.json') { |response| response.code == '200' }
      key = Ed25519::SigningKey.new([File.read(File.join(@src, 'signing_key'))].pack('H*'))
      @session_token = JWT.encode({ sub: 'operator', login: 'operator', role: 'admin', exp: Time.now.to_i + 300 }, key, 'EdDSA')
      spawn_server(backend_file, @backend_port, AUDIENCE: 'insight')
      spawn_server(backend_file, @other_port, AUDIENCE: 'previously-unknown-service')
      @auth_pid = @pids.first

      middlewares = {
        'basic' => { 'basicAuth' => { 'users' => ["operator:{SHA}#{Base64.strict_encode64(Digest::SHA1.digest('test-password'))}"] } }
      }
      routers = {}
      [['host', 'insight.test', '', 'insight'],
       ['prefix', 'prefix.test', '/insight', 'insight'],
       ['map', 'map.test', '/map/insight', 'insight'],
       ['other', 'other.test', '', 'previously-unknown-service']].each do |name, host, prefix, audience|
        address = "http://127.0.0.1:#{@auth_port}/auth/assertion?#{URI.encode_www_form(aud: audience, strip_prefix: prefix)}"
        middlewares["auth-#{name}"] = { 'forwardAuth' => {
          'address' => address, 'trustForwardHeader' => false,
          'authRequestHeaders' => ['Cookie'],
          'authResponseHeadersRegex' => '(?i)^X-(Auth-Jwt|AuthSlim|Token)$'
        } }
        chain = ["auth-#{name}", 'basic']
        unless prefix.empty?
          middlewares["rewrite-#{name}"] = { 'replacePathRegex' => { 'regex' => "^#{prefix}(.*)", 'replacement' => '$1' } }
          chain << "rewrite-#{name}"
        end
        routers[name] = { 'rule' => "Host(#{host.dump})", 'service' => name == 'other' ? 'other' : 'insight', 'middlewares' => chain }
      end
      config = { 'http' => {
        'routers' => routers, 'middlewares' => middlewares,
        'services' => {
          'insight' => { 'loadBalancer' => { 'servers' => [{ 'url' => "http://127.0.0.1:#{@backend_port}" }] } },
          'other' => { 'loadBalancer' => { 'servers' => [{ 'url' => "http://127.0.0.1:#{@other_port}" }] } }
        }
      } }
      configuration = File.join(@directory, 'traefik.yml')
      File.write(configuration, YAML.dump(config))
      @pids << Process.spawn(ENV.fetch('TRAEFIK_BINARY'), "--entrypoints.web.address=127.0.0.1:#{@proxy_port}",
                             '--entrypoints.web.forwardedheaders.insecure=true',
                             '--entrypoints.web.http.encodedcharacters.allowencodedslash=true',
                             "--providers.file.filename=#{configuration}", '--log.level=ERROR',
                             out: File.join(@directory, 'traefik.log'), err: [:child, :out])
      await_response(@proxy_port) { |response| response.code == '200' }
    end

    after(:context) do
      @pids&.reverse_each do |pid|
        Process.kill('TERM', pid)
      rescue Errno::ESRCH
        nil
      end
      @pids&.reverse_each do |pid|
        Timeout.timeout(5) { Process.wait(pid) }
      rescue Timeout::Error
        Process.kill('KILL', pid)
        Process.wait(pid)
      rescue Errno::ECHILD, Errno::ESRCH
        nil
      end
    end

    it 'validates all three deployed path mappings including raw encoding and empty queries' do
      [['insight.test', ''], ['prefix.test', '/insight'], ['map.test', '/map/insight']].each do |host, prefix|
        [['/x%2Fy?a=1&a=2', '/x%2Fy?a=1&a=2'], ['/x%2fy?a=+&a=%20', '/x%2Fy?a=+&a=%20'],
         ['/?', '/?'], ['/', '/']].each do |suffix, expected|
          response = http(@proxy_port, "#{prefix}#{suffix}", host:)
          expect(response.code).to eq('200'), "#{host} #{suffix}: #{response.body}"
          body = JSON.parse(response.body)
          expect(body['target']).to eq(expected)
          expect(body['identity']).to include('sub' => 'operator', 'aud' => 'insight')
          expect(body['assertion_present']).to be(false)
          expect(response['X-AUTH-JWT']).to be_nil
        end
        next if prefix.empty?

        expect(http(@proxy_port, prefix, host:).code).to eq('200')
      end
    end

    it 'reconstructs forwarded metadata and strips a caller-provided assertion' do
      response = http(@proxy_port, '/private?aud=client', headers: {
        'X-Forwarded-Uri' => '/forged', 'X-Forwarded-Method' => 'POST',
        'X-AUTH-JWT' => 'forged', 'X-AuthSlim' => 'authorized', 'X-Audience' => 'forged'
      })
      expect(response.code).to eq('200'), response.body
      expect(JSON.parse(response.body)['target']).to eq('/private?aud=client')
      expect(http(@proxy_port, '/', cookie: false).code).to eq('302')
      expect(http(@proxy_port, '/', basic: false).code).to eq('401')
    end

    it 'denies direct access without an assertion and consumes direct assertions once' do
      expect(http(@backend_port, '/').code).to eq('401')
      expect(http(@backend_port, '/', headers: { 'X-AUTH-JWT' => 'forged' }).code).to eq('401')
      minted = http(@auth_port, '/auth/assertion?aud=insight', headers: {
        'X-Forwarded-Method' => 'GET', 'X-Forwarded-Uri' => '/private', 'X-Forwarded-Host' => 'insight.test'
      })
      expect(minted.code).to eq('200')
      headers = { 'X-AUTH-JWT' => minted['X-AUTH-JWT'] }
      expect(http(@backend_port, '/private', headers:).code).to eq('200')
      expect(http(@backend_port, '/private', headers:).code).to eq('401')
      expect(http(@other_port, '/private', headers:).code).to eq('401')
    end

    it 'authenticates a previously unknown service without changing the issuer process' do
      response = http(@proxy_port, '/private', host: 'other.test')
      expect(response.code).to eq('200'), response.body
      expect(JSON.parse(response.body)['identity']['aud']).to eq('previously-unknown-service')
      expect(Process.kill(0, @auth_pid)).to eq(1)
    end

    it 'bounds real key responses and refuses redirects to another key location' do
      fetch = OAuthSlim::AuthJwtMiddleware::KeyEndpoint
      %w[redirect oversized].each do |path|
        endpoint = fetch.new("http://127.0.0.1:#{@auth_port}/fixture/#{path}")
        expect { endpoint.call }.to raise_error(OAuthSlim::AuthJwtMiddleware::Unavailable)
      end
    end

    it 'authenticates an actual websocket upgrade through the path rewrite' do
      socket = TCPSocket.new('127.0.0.1', @proxy_port)
      socket.write("GET /insight/ws?x=1 HTTP/1.1\r\nHost: prefix.test\r\nCookie: auth_token=#{@session_token}\r\nAuthorization: Basic #{Base64.strict_encode64('operator:test-password')}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
      headers = Timeout.timeout(5) do
        lines = []
        loop do
          line = socket.gets("\r\n")
          break if line.nil? || line == "\r\n"

          lines << line
        end
        lines.join
      end
      expect(headers).to start_with('HTTP/1.1 101'), headers
      expect(headers.downcase).to include('sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=')
    ensure
      socket&.close
    end
  end
end
