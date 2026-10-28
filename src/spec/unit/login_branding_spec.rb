# frozen_string_literal: true

require_relative '../spec_helper'
require 'logger'
require 'cgi'
require 'tmpdir'
require 'fileutils'
require 'rack/mock'
require 'sinatra/base'
require 'slim'
require 'sassc'
require_relative '../../i18n_setup'
require_relative '../../auth/authorization_code'

ENV['FORWARD_OAUTH_AUTH_URL'] = '/authorize'
LOGGER = Logger.new(File::NULL) unless defined?(LOGGER)
require_relative '../../auth/users_auth'

class LoginBrandingSpecApp < Sinatra::Base
  set :environment, :test
  set :raise_errors, true
  set :show_exceptions, false
  set :sessions, { secret: 'login-branding-spec-secret-' * 4 }
  set :views, File.expand_path('../../views', __dir__)
  register LocaleSupport

  helpers AuthorizationCode, UsersAuth
  helpers do
    def get_token = nil
    def valid_token?(_token) = false
    def valid_redirect_uri!(value) = URI.parse(value)
    def users_data = { 'users' => [{ 'test_user' => { 'password' => 'test-password' } }] }
  end

  get('/unbranded') { slim :index }
  get('/telegram-preview') { slim :telegram_auth, locals: { auth_code: 'test-correlation' } }
end

RSpec.describe LoginBranding do
  let(:request) { Rack::MockRequest.new(LoginBrandingSpecApp) }
  let(:context) do
    { redirect_uri: 'https://opt.test/packages', client_id: 'opt', response_type: 'code',
      scope: 'openid profile', state: 'state<&"', nonce: 'nonce<&"' }
  end
  let(:opt_settings) do
    { 'LOGIN_APP_NAME' => 'OPT', 'LOGIN_LOGO_URL' => '/branding/opt.svg',
      'LOGIN_PRIMARY_COLOR' => '#35654f', 'LOGIN_BACKGROUND_COLOR' => '#f7f9f8',
      'LOGIN_DEFAULT_LOCALE' => 'ru', 'LOGIN_SHOW_BUILD' => 'false' }
  end
  let(:logo_svg) { '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M7 3h10l3 18H4z"/></svg>' }

  around do |example|
    previous_public_folder = LoginBrandingSpecApp.public_folder
    Dir.mktmpdir('login-branding-spec-') do |public_folder|
      @public_folder = public_folder
      LoginBrandingSpecApp.set :public_folder, public_folder
      I18n.with_locale(:en) { example.run }
    end
  ensure
    LoginBrandingSpecApp.set :public_folder, previous_public_folder
  end

  before do
    AUTH_CODES.clear
    allow(LoginBranding).to receive(:config).and_return(described_class.new({}))
  end

  after { AUTH_CODES.clear }

  it 'renders the reference design with default branding when unconfigured' do
    response = login
    expect(response.status).to eq(200)
    expect(response.body).to include('Welcome back', 'Sign in with your username and password.', 'Build v ', '<title>Auth Slim</title>', '>System</span>', '>Username</label>', '>Sign in</span>')
    expect(response.body).not_to include('<img')
    expect(response.body).to include('<body class="password-login-page" style="">')
    expect(described_class.new({}).style).to eq('')
  end

  it 'renders OPT branding with the configured default language and hidden build label' do
    configure(opt_settings)
    body = login.body
    expect(body).to include('<html lang="ru">', '<title>OPT</title>', 'Вход в OPT', '/branding/opt.svg', '--color-primary: #35654f')
    expect(body).not_to include('Build v ')
  end

  {
    'root deployment' => ['/authorize', false],
    'preserved proxy prefix' => ['/opt_oauth/authorize', false],
    'stripped proxy prefix' => ['/opt_oauth/authorize', true]
  }.each do |deployment, (path, strip_prefix)|
    it "embeds the mounted logo without another request with a #{deployment}" do
      install_logo
      configure('LOGIN_APP_NAME' => 'OPT')
      app = if strip_prefix
              ->(env) { LoginBrandingSpecApp.call(env.merge('PATH_INFO' => env['PATH_INFO'].delete_prefix('/opt_oauth'))) }
            else
              LoginBrandingSpecApp
            end
      client = Rack::MockRequest.new(app)
      original = "http://example.org#{path}?#{URI.encode_www_form(context)}"
      body = client.get(original).body
      expect(body).to include('Sign in to OPT')
      encoded = body.match(/src="data:image\/svg\+xml;base64,([^"]+)"/)[1]
      expect(Base64.strict_decode64(encoded)).to eq(logo_svg)
    end
  end

  it 'uses an explicit logo URL in preference to the mounted default' do
    install_logo
    configure(opt_settings.merge('LOGIN_LOGO_URL' => 'https://static.example.org/custom.svg'))
    expect(login.body).to include('src="https://static.example.org/custom.svg"')
    expect(login.body).not_to include('src="data:image/svg+xml;')
  end

  it 'falls back to the built-in icon when the mounted logo is removed' do
    install_logo
    expect(login.body).to include('src="data:image/svg+xml;base64,')
    File.delete(File.join(@public_folder, 'branding', 'logo.svg'))
    expect(login.body).not_to include('<img')
  end

  it 'embeds SVG as image data without inserting its markup into the page' do
    install_logo
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("logo-script")</script></svg>'
    File.write(File.join(@public_folder, 'branding', 'logo.svg'), svg)
    body = login.body
    expect(body).to include("src=\"data:image/svg+xml;base64,#{Base64.strict_encode64(svg)}\"")
    expect(body).not_to include('logo-script')
  end

  it 'honors a session language selection over the deployment default' do
    configure(opt_settings)
    location = "/authorize?#{URI.encode_www_form(context)}"
    selected = request.get("#{location}&locale=en")
    cookie = Array(selected['set-cookie']).map { |value| value.split(';', 2).first }.join('; ')
    body = request.get(location, 'HTTP_COOKIE' => cookie).body
    expect(body).to include('<html lang="en">', 'Sign in to OPT')
  end

  {
    'root deployment' => ['/authorize', false],
    'preserved proxy prefix' => ['/opt_oauth/authorize', false],
    'stripped proxy prefix' => ['/opt_oauth/authorize', true]
  }.each do |deployment, (path, strip_prefix)|
    it "switches language without a Referer and preserves the OAuth query with a #{deployment}" do
      app = if strip_prefix
              ->(env) { LoginBrandingSpecApp.call(env.merge('PATH_INFO' => env['PATH_INFO'].delete_prefix('/opt_oauth'))) }
            else
              LoginBrandingSpecApp
            end
      client = Rack::MockRequest.new(app)
      query = context.to_a + [
        ['code_challenge', 'challenge-_/+'], ['code_challenge_method', 'S256'],
        ['resource', 'https://one.test'], ['resource', 'https://two.test'],
        ['locale', 'en'], ['locale', 'en']
      ]
      original = "http://example.org#{path}?#{URI.encode_www_form(query)}"
      href = language_link(client.get(original), 'ru')
      expect(href).to start_with('?')
      target = URI.join(original, href)
      expect(target.path).to eq(path)
      expected = query.reject { |name, _value| name == 'locale' }.map { |name, value| [name.to_s, value] }
      expect(URI.decode_www_form(target.query)).to eq(expected + [['locale', 'ru']])

      switched = client.get(target.to_s)
      expect(switched.status).to eq(200)
      expect(switched['location']).to be_nil
      expect(switched.body).to include('<html lang="ru">', 'С возвращением')
    end
  end

  it 'keeps the selected language and OAuth context when switching after a failed form submission' do
    original = "/opt_oauth/authorize?#{URI.encode_www_form(context.merge(locale: 'ru', code_challenge: 'unchanged', code_challenge_method: 'S256'))}"
    failed = request.post(original, params: context.merge(username: 'test_user', password: 'wrong'))
    expect(failed.body).to include('<html lang="ru">', 'Неверный логин/пароль')
    href = language_link(failed, 'en')
    query = URI.decode_www_form(URI.parse(href).query).to_h
    expect(query).to include(context.transform_keys(&:to_s).merge('locale' => 'en', 'code_challenge' => 'unchanged', 'code_challenge_method' => 'S256'))
    expect(query.keys & %w[username password]).to be_empty

    switched = request.get(URI.join("http://example.org#{original}", href).to_s)
    expect(switched.status).to eq(200)
    expect(switched.body).to include('<html lang="en">', 'Welcome back')
  end

  it 'recovers authorization fields from a POST without a query without copying credentials into language links' do
    failed = request.post('/authorize', params: context.merge(username: 'test_user', password: 'wrong'))
    href = language_link(failed, 'ru')
    query = URI.decode_www_form(URI.parse(href).query).to_h
    expect(query).to eq(context.transform_keys(&:to_s).merge('locale' => 'ru'))
    expect(request.get("/authorize#{href}").body).to include('<html lang="ru">')
  end

  it 'uses localized copy, then generic copy, then the translated default' do
    configure(opt_settings.merge('LOGIN_TITLE' => 'Welcome', 'LOGIN_TITLE_RU' => 'Добро пожаловать', 'LOGIN_SUBTITLE' => 'Account access'))
    expect(login.body).to include('Добро пожаловать', 'Account access')
    config = LoginBranding.config
    expect(config.text('TITLE', :en, 'Fallback')).to eq('Welcome')
    expect(config.text('UNSET', :en, 'Fallback')).to eq('Fallback')
  end

  it 'escapes configured text and authorization fields as HTML' do
    configure(opt_settings.merge('LOGIN_APP_NAME' => '<script>alert(1)</script>', 'LOGIN_SUBTITLE_RU' => '<b>Welcome</b>'))
    body = login.body
    expect(body).to include('&lt;script&gt;alert(1)&lt;/script&gt;', '&lt;b&gt;Welcome&lt;/b&gt;', 'state&lt;&amp;&quot;', 'nonce&lt;&amp;&quot;')
    expect(body).not_to include('<script>alert(1)</script>', '<b>Welcome</b>')
  end

  it 'keeps errors branded and preserves every authorization field on retry' do
    configure(opt_settings)
    response = request.post('/authorize', params: context.merge(username: 'test_user', password: 'wrong'))
    expect(response.status).to eq(200)
    expect(response.body).to include('Вход в OPT', 'role="alert"', 'Неверный логин/пароль')
    context.each do |key, value|
      expect(response.body).to include("name=\"#{key}\" type=\"hidden\" value=\"#{Rack::Utils.escape_html(value)}\"")
    end
    expect(AUTH_CODES).to be_empty
  end

  it 'keeps successful login and its OAuth context unchanged' do
    configure(opt_settings)
    response = request.post('/authorize', params: context.merge(username: 'test_user', password: 'test-password'))
    expect(response.status).to eq(303)
    callback = URI.parse(response['location'])
    query = URI.decode_www_form(callback.query).to_h
    expect([callback.host, callback.path, query['state']]).to eq(['opt.test', '/packages', context[:state]])
    expect(AUTH_CODES.fetch(query.fetch('code'))).to include(login: 'test_user', client_id: 'opt', nonce: context[:nonce], requested_scope: 'openid profile')
  end

  it 'does not brand other pages using the shared layout' do
    configure(opt_settings)
    body = request.get('/unbranded').body
    expect(body).to include('<title>Auth Slim</title>')
    expect(body).not_to include('--color-primary: #35654f', '/branding/opt.svg')
  end

  it 'uses the same locale selection and query-only links on Telegram login' do
    path = "/telegram-preview?#{URI.encode_www_form(context.merge(locale: 'ru'))}"
    response = request.get(path)
    expect(response.status).to eq(200)
    expect(response.body).to include('<html lang="ru">', 'Вход в систему', 'weblogin_test-correlation')
    expect(response.body).not_to include('href="/locale/')
    expect(response.body.scan(/<a\b[^>]*class="locale-link[^>]*>/)).to all(include('href="?'))
    expect(response.body).to include('&amp;locale=en', '&amp;locale=ru')
  end

  it 'enables the CSS palette from just the app name, primary color, and language' do
    configure('LOGIN_APP_NAME' => 'OPT', 'LOGIN_PRIMARY_COLOR' => '#32664d', 'LOGIN_DEFAULT_LOCALE' => 'ru')
    expect(LoginBranding.config.style).to eq('--color-primary: #32664d')
    expect(login.body).to include('<body class="password-login-page custom-palette" style="--color-primary: #32664d">',
                                 'Вход в OPT', 'Войдите по логину и паролю.', 'Build v ')
  end

  it 'gives every explicit color override precedence over the generated palette' do
    settings = {
      'LOGIN_PRIMARY_COLOR' => '#32664d', 'LOGIN_PRIMARY_HOVER_COLOR' => '#123',
      'LOGIN_PRIMARY_TEXT_COLOR' => '#fed', 'LOGIN_BACKGROUND_COLOR' => '#fefefe',
      'LOGIN_CARD_COLOR' => '#fafafa', 'LOGIN_TEXT_COLOR' => '#111',
      'LOGIN_MUTED_COLOR' => '#555', 'LOGIN_BORDER_COLOR' => '#ddd'
    }
    expected = settings.to_h { |key, value| [described_class::COLORS.fetch(key.delete_prefix('LOGIN_')), value] }
    configure(settings)
    expect(style_colors(LoginBranding.config)).to eq(expected)
    expect(login.body).to include("style=\"#{LoginBranding.config.style}\"")
  end

  it 'keeps the existing defaults when only an individual non-primary color is overridden' do
    configure('LOGIN_BORDER_COLOR' => '#ddd')
    expect(login.body).to include('<body class="password-login-page" style="--color-border: #ddd">')
  end

  it 'rejects CSS injection and unsupported boolean settings' do
    expect { described_class.new('LOGIN_PRIMARY_COLOR' => '#fff; background: url(https://example.org)') }.to raise_error(ArgumentError, /LOGIN_PRIMARY_COLOR/)
    expect { described_class.new('LOGIN_SHOW_BUILD' => 'no') }.to raise_error(ArgumentError, /LOGIN_SHOW_BUILD/)
  end

  it 'accepts public logo paths and HTTPS URLs, and rejects unsafe URL forms' do
    ['/branding/logo.svg', '/auth/assets/logo.svg', 'https://static.example.org/logo.svg'].each do |url|
      expect(described_class.new('LOGIN_LOGO_URL' => url).logo_url).to eq(url)
    end
    ['//example.org/logo.svg', '/\\example.org/logo.svg', 'javascript:alert(1)', 'data:image/svg+xml,abc', 'https://user:pass@example.org/logo.svg', 'http://example.org/logo.svg'].each do |url|
      expect { described_class.new('LOGIN_LOGO_URL' => url) }.to raise_error(ArgumentError, /LOGIN_LOGO_URL/)
    end
  end

  it 'treats blank settings as unset' do
    config = described_class.new('LOGIN_APP_NAME' => ' ', 'LOGIN_PRIMARY_COLOR' => '', 'LOGIN_SHOW_BUILD' => '')
    expect(config.app_name).to be_nil
    expect(config.style).to eq('')
    expect(config.show_build?).to be(true)
  end

  def configure(values)
    allow(LoginBranding).to receive(:config).and_return(described_class.new(values))
  end

  def login = request.get("/authorize?#{URI.encode_www_form(context)}")

  def style_colors(config)
    config.style.split('; ').to_h { |declaration| declaration.split(': ', 2) }
  end

  def install_logo
    FileUtils.mkdir_p(File.join(@public_folder, 'branding'))
    File.write(File.join(@public_folder, 'branding', 'logo.svg'), logo_svg)
  end

  def language_link(response, locale)
    anchor = response.body.scan(/<a\b[^>]*>/).find { |tag| tag.include?("lang=\"#{locale}\"") }
    CGI.unescapeHTML(anchor.match(/href="([^"]*)"/)[1])
  end
end
