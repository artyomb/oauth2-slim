# frozen_string_literal: true

require 'uri'
require 'base64'

class LoginBranding
  COLORS = {
    'PRIMARY_COLOR' => '--color-primary',
    'PRIMARY_HOVER_COLOR' => '--login-primary-hover',
    'PRIMARY_TEXT_COLOR' => '--login-primary-text',
    'BACKGROUND_COLOR' => '--color-background',
    'CARD_COLOR' => '--color-background-card',
    'TEXT_COLOR' => '--color-text',
    'MUTED_COLOR' => '--color-text-muted',
    'BORDER_COLOR' => '--color-border'
  }.freeze

  def self.config = @config ||= new

  def initialize(env = ENV)
    @values = env.to_h.filter_map do |key, value|
      next unless key.start_with?('LOGIN_') && !value.to_s.strip.empty?

      [key.delete_prefix('LOGIN_'), value.to_s.strip.freeze]
    end.to_h.freeze
    validate!
  end

  def app_name = @values['APP_NAME']
  def primary_color = @values['PRIMARY_COLOR']

  def logo_url(public_folder = File.expand_path('public', __dir__))
    return @values['LOGO_URL'] if @values['LOGO_URL']

    path = File.join(public_folder, 'branding/logo.svg')
    return unless File.file?(path) && File.readable?(path)

    "data:image/svg+xml;base64,#{Base64.strict_encode64(File.binread(path))}"
  end

  def default_locale = @values.fetch('DEFAULT_LOCALE', 'en').to_sym
  def show_build? = @values.fetch('SHOW_BUILD', 'true') == 'true'

  def text(key, locale, fallback)
    @values["#{key}_#{locale.to_s.upcase}"] || @values[key] || fallback
  end

  def style = @values.slice(*COLORS.keys).map { |key, value| "#{COLORS.fetch(key)}: #{value}" }.join('; ')

  private

  def validate!
    COLORS.each_key do |key|
      next unless @values[key]
      next if @values[key].match?(/\A#(?:[0-9a-f]{3}|[0-9a-f]{6})\z/i)

      raise ArgumentError, "LOGIN_#{key} must be a 3- or 6-digit hex color"
    end
    unless %w[true false].include?(@values.fetch('SHOW_BUILD', 'true'))
      raise ArgumentError, 'LOGIN_SHOW_BUILD must be true or false'
    end
    validate_logo! if @values['LOGO_URL']
  end

  def validate_logo!
    uri = URI.parse(logo_url)
    local = logo_url.start_with?('/') && !logo_url.start_with?('//') && !uri.host && !uri.scheme
    remote = uri.scheme == 'https' && !uri.host.to_s.empty? && !uri.userinfo
    raise ArgumentError unless (local || remote) && !logo_url.match?(/[\\\s]/)
  rescue URI::InvalidURIError, ArgumentError
    raise ArgumentError, 'LOGIN_LOGO_URL must be a root-relative path or an HTTPS URL without credentials'
  end
end
