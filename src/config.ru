#!/usr/bin/env ruby
# require_relative 'src/server'
require 'sinatra'
require 'slim'
require 'rack/sassc'
require_relative 'i18n_setup'
require_relative 'auth/auth20'
require_relative 'auth/auth_forward'
require_relative 'auth/openid_connect'

require 'stack-service-base'
StackServiceBase.rack_setup self

enable :sessions

before do
  I18n.locale = session[:locale] || I18n.default_locale
end

helpers Auth20, AuthForward, OpenIDConnect
helpers do
  def t(key, options = {}) = I18n.t(key, **options)
end

not_found { '404 page' }

get '/', &-> { slim :index }
get '*favicon.ico', &-> { '' }
get %r{.*/locale/(.*)} do |locale|
  session[:locale] = locale.to_sym if I18n.available_locales.include?(locale.to_sym)
  redirect back
end

disable :show_exceptions unless ENV['DEBUG']
error do
  status 500
  $stderr.puts "Exception: #{env['sinatra.error']}"
  $stderr.puts "Exception backtrace: #{env['sinatra.error'].backtrace[0..10].join("\n")}"
  { error: "Internal server error", message: env['sinatra.error'].message, backtrace: env['sinatra.error'].backtrace[0..10] }.to_json
end

run Sinatra::Application