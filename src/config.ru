#!/usr/bin/env ruby
# require_relative 'src/server'
require 'sinatra'
require 'slim'
require 'rack/sassc'
require_relative 'auth/auth20'
require_relative 'auth/auth_forward'
require_relative 'auth/openid_connect'

require 'stack-service-base'

StackServiceBase.rack_setup self

helpers Auth20, AuthForward, OpenIDConnect

not_found { '404 page' }

get '/', &-> { slim :index }
get '*favicon.ico', &-> { '' }

disable :show_exceptions unless ENV['DEBUG']
error do
  status 500
  $stderr.puts "Exception: #{env['sinatra.error']}"
  $stderr.puts "Exception backtrace: #{env['sinatra.error'].backtrace[0..10].join("\n")}"
  { error: "Internal server error", message: env['sinatra.error'].message, backtrace: env['sinatra.error'].backtrace[0..10] }.to_json
end

run Sinatra::Application