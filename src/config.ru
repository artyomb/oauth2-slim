#!/usr/bin/env ruby
# require_relative 'src/server'
ENV['TZ'] = 'UTC'

require_relative 'auth/log_safety'
require 'stack-service-base'
LogSafety.install_stack_service_base_header_logger

require 'sinatra'
require 'slim'
require 'rack/sassc'
require_relative 'i18n_setup'
require_relative 'auth/auth20'
require_relative 'auth/auth_forward'
require_relative 'auth/openid_connect'
require_relative 'authorization/controller'
require_relative 'authorization/same_origin'

use Authorization::SameOrigin, admin_path: Authorization::PolicyController::ADMIN_PATH
StackServiceBase.rack_setup self

register LocaleSupport

helpers Auth20, AuthForward, OpenIDConnect
set :policy_repository, Authorization::PolicyRepository.new(DB) if defined?(OAuthUser) && defined?(DB)
helpers Authorization::PolicyController

not_found { '404 page' }

get '/', &-> { slim :index }
get '*favicon.ico', &-> { '' }
get %r{.*/locale/(.*)} do |locale|
  selected = supported_locale(locale)
  session[:locale] = selected if selected
  redirect back
end

disable :show_exceptions unless ENV['DEBUG']
error do
  status 500
  error = env['sinatra.error']
  LOGGER.error "Unhandled exception: #{LogSafety.exception_message(error)}"
  LOGGER.debug "Unhandled exception backtrace: #{error.backtrace&.first(10)&.join("\n")}" if ENV['DEBUG']
  { error: 'Internal server error' }.to_json
end

run Sinatra::Application
