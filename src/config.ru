#!/usr/bin/env ruby
# require_relative 'src/server'
require 'sinatra'
require 'slim'
require 'rack/sassc'
require_relative 'auth/auth20'
require_relative 'auth/auth_forward'

require 'stack-service-base'

StackServiceBase.rack_setup self

helpers Auth20, AuthForward

not_found { '404 page' }

get '/', &-> { slim :index }
get '*favicon.ico', &-> { '' }

run Sinatra::Application