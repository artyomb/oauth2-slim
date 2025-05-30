#!/usr/bin/env ruby
# require_relative 'src/server'
require 'sinatra'
require 'slim'
require 'rack/sassc'
require_relative 'auth/auth20'
require_relative 'auth/auth_forward'

require 'stack-service-base'

StackServiceBase.rack_setup self

Slim::Engine.set_options pretty: true
use Rack::Static, urls: ["/"], root: "public", cascade: true
use Rack::SassC, css_location: "#{__dir__}/public/css", scss_location: "#{__dir__}/public/css",
    create_map_file: true, syntax: :sass, check: true, cache: ENV['RACK_ENV'] == 'production'
# use Rack::Session::Cookie, key: 'rack.session', path: '/', secret: 'secret_stuff123'

helpers Auth20, AuthForward

not_found { '404 page' }

get '/', &-> { slim :index }
get '*favicon.ico', &-> { '' }

run Sinatra::Application