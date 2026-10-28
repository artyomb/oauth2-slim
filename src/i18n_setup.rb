require 'i18n'
require 'uri'
require_relative 'login_branding'

I18n.load_path = Dir["#{__dir__}/locales/*.yml"]
I18n.available_locales = Dir["#{__dir__}/locales/*.yml"].map { File.basename(_1, '.yml').to_sym }
I18n.default_locale = LoginBranding.config.default_locale
I18n.backend.load_translations

module LocaleSupport
  def self.registered(app)
    options = app.sessions.respond_to?(:to_hash) ? app.sessions.to_hash.dup : {}
    secret = ENV['SESSION_SECRET']
    cookie_name = ENV['SESSION_COOKIE_NAME']
    unless secret.to_s.empty?
      raise ArgumentError, 'SESSION_SECRET must contain at least 64 bytes' if secret.bytesize < 64

      options[:secret] = secret
    end
    unless cookie_name.to_s.empty?
      raise ArgumentError, 'SESSION_COOKIE_NAME must contain only letters, digits, dots, underscores or hyphens' unless cookie_name.match?(/\A[a-zA-Z0-9_.-]+\z/)

      options[:key] = cookie_name
    end

    app.set :sessions, options
    app.helpers self
    app.before do
      selected = supported_locale(request.GET['locale'])
      session[:locale] = selected if selected
      @request_locale = selected || supported_locale(session[:locale]) || LoginBranding.config.default_locale
    end
  end

  def supported_locale(value) = I18n.available_locales.find { |locale| locale.to_s == value.to_s }
  def current_locale = @request_locale || LoginBranding.config.default_locale

  # I18n's active locale is thread-local; Falcon can interleave request fibers on that thread.
  def t(key, options = {}) = I18n.t(key, **options, locale: current_locale)

  def locale_url(locale, authorization_fields = {})
    query = URI.decode_www_form(request.query_string).reject { |name, _value| name == 'locale' }
    missing = authorization_fields.transform_keys(&:to_s).except(*query.map(&:first))
    "?#{URI.encode_www_form(query + missing.to_a + [['locale', locale.to_s]])}"
  end
end
