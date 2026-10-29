# frozen_string_literal: true

require_relative '../spec_helper'
require 'rack/mock'
require 'sinatra/base'
require_relative '../../i18n_setup'

RSpec.describe LocaleSupport do
  before do
    allow(LoginBranding).to receive(:config).and_return(LoginBranding.new({}))
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('SESSION_SECRET').and_return(nil)
    allow(ENV).to receive(:[]).with('SESSION_COOKIE_NAME').and_return(nil)
    allow(ENV).to receive(:fetch).and_call_original
    allow(ENV).to receive(:fetch).with('COOKIE_TOKEN_NAME', 'auth_token').and_return('auth_token')
  end

  it 'prefers explicit selection, then the saved preference, then the deployment default' do
    allow(LoginBranding).to receive(:config).and_return(LoginBranding.new('LOGIN_DEFAULT_LOCALE' => 'ru'))
    client = Rack::MockRequest.new(build_app)
    expect(client.get('/').body).to eq('ru')
    selected = client.get('/?locale=en')
    expect(selected.body).to eq('en')
    expect(client.get('/', 'HTTP_COOKIE' => cookie(selected)).body).to eq('en')
    expect(client.get('/?locale=ru', 'HTTP_COOKIE' => cookie(selected)).body).to eq('ru')
    expect(client.get('/').body).to eq('ru')
  end

  it 'ignores unsupported and structured locale values without overwriting the saved preference' do
    client = Rack::MockRequest.new(build_app)
    selected = client.get('/?locale=ru')
    %w[locale=fr locale= locale[]=en locale[language]=en].each do |query|
      response = client.get("/?#{query}", 'HTTP_COOKIE' => cookie(selected))
      expect(response.status).to eq(200)
      expect(response.body).to eq('ru')
    end
  end

  it 'falls back safely if a saved language is no longer supported' do
    client = Rack::MockRequest.new(build_app)
    selected = client.get('/remember-removed')
    expect(client.get('/', 'HTTP_COOKIE' => cookie(selected)).body).to eq('en')
  end

  it 'restores the previous locale after a request fails' do
    client = Rack::MockRequest.new(build_app)
    I18n.with_locale(:en) do
      expect { client.get('/failure?locale=ru') }.to raise_error('Failure in ru')
      expect(I18n.locale).to eq(:en)
    end
  end

  it 'keeps languages separate across interleaved requests' do
    client = Rack::MockRequest.new(build_app)
    requests = %w[ru en].map do |locale|
      Fiber.new { client.get("/interleaved?locale=#{locale}") }
    end
    expected = %i[ru en].map { |locale| I18n.t('auth.password_login_button', locale:) }
    expect(requests.map(&:resume)).to eq(expected)
    expect(requests.map { |fiber| fiber.resume.body }).to eq(expected)
  end

  it 'retains the preference across independently initialized apps using the same configured session secret' do
    allow(ENV).to receive(:[]).with('SESSION_SECRET').and_return('stable-session-test-secret-' * 4)
    allow(ENV).to receive(:[]).with('SESSION_COOKIE_NAME').and_return('opt.locale_session')
    first = Rack::MockRequest.new(build_app)
    second = Rack::MockRequest.new(build_app)
    selected = first.get('/?locale=ru')
    expect(cookie(selected)).to start_with('opt.locale_session=')
    expect(second.get('/', 'HTTP_COOKIE' => cookie(selected)).body).to eq('ru')
  end

  it 'derives distinct session cookies from each deployment token cookie name' do
    main = Rack::MockRequest.new(build_app)
    allow(ENV).to receive(:fetch).with('COOKIE_TOKEN_NAME', 'auth_token').and_return('map_auth')
    map = Rack::MockRequest.new(build_app)

    main_locale = main.get('/?locale=ru')
    map_locale = map.get('/?locale=en', 'HTTP_COOKIE' => cookie(main_locale))
    expect(cookie(main_locale)).to start_with('auth_token.session=')
    expect(cookie(map_locale)).to start_with('map_auth.session=')

    cookies = [cookie(main_locale), cookie(map_locale), 'auth_token=main-token', 'map_auth=map-token'].join('; ')
    expect(main.get('/', 'HTTP_COOKIE' => cookies).body).to eq('ru')
    expect(map.get('/', 'HTTP_COOKIE' => cookies).body).to eq('en')
  end

  it 'isolates deployments on the same hostname using distinct cookie names' do
    allow(ENV).to receive(:[]).with('SESSION_SECRET').and_return('shared-session-test-secret-' * 4)
    allow(ENV).to receive(:[]).with('SESSION_COOKIE_NAME').and_return('opt.session')
    opt = Rack::MockRequest.new(build_app)
    allow(ENV).to receive(:[]).with('SESSION_COOKIE_NAME').and_return('other.session')
    other = Rack::MockRequest.new(build_app)
    selected = opt.get('/?locale=ru')
    expect(other.get('/', 'HTTP_COOKIE' => cookie(selected)).body).to eq('en')
  end

  it 'rejects unusable session settings at startup' do
    allow(ENV).to receive(:[]).with('SESSION_SECRET').and_return('short')
    expect { build_app }.to raise_error(ArgumentError, /SESSION_SECRET/)
    allow(ENV).to receive(:[]).with('SESSION_SECRET').and_return(nil)
    allow(ENV).to receive(:[]).with('SESSION_COOKIE_NAME').and_return('invalid;name')
    expect { build_app }.to raise_error(ArgumentError, /SESSION_COOKIE_NAME/)
  end

  def build_app
    Class.new(Sinatra::Base) do
      set :environment, :test
      set :raise_errors, true
      set :show_exceptions, false
      set :session_secret, SecureRandom.hex(64)
      register LocaleSupport
      get('/') { current_locale.to_s }
      get('/remember-removed') { session[:locale] = :removed; '' }
      get('/failure') { raise "Failure in #{current_locale}" }
      get '/interleaved' do
        Fiber.yield t('auth.password_login_button')
        t('auth.password_login_button')
      end
    end
  end

  def cookie(response)
    Array(response['set-cookie']).map { |value| value.split(';', 2).first }.join('; ')
  end
end
