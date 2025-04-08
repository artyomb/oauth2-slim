require 'sinatra'
require 'sinatra/base'
require 'sinatra/namespace'
require 'sinatra/reloader'
require 'rack/sassc'
require 'slim'
require 'net/http'
require 'jwt'
require 'json'
require_relative 'ajax'
require 'digest'
require_relative 'auth/auth20'
require_relative 'auth/auth_forward'

Slim::Engine.set_options pretty: true
class SinatraSrv < Sinatra::Base
  helpers Ajax::Helpers
  helpers Auth20
  helpers AuthForward

  register Sinatra::Namespace
  register Sinatra::Reloader
  enable :reloader
  disable :show_exceptions
  # enable :sessions

  use Rack::SassC, css_location: "#{__dir__}/public/css", scss_location: "#{__dir__}/public/css", create_map_file: true, syntax: :sass, check: true
  # use Rack::Session::Cookie, :key => "rack.session", :path => "/", secret: 'secret_stuff123'

  set :root, __dir__

  error do
    "<h1>Error: #{env['sinatra.error']}</h1> <pre>#{env['sinatra.error'].backtrace.join("\n")}</pre>"
  end

  not_found { '404 page' }

  get '/', &-> { slim :index }
  get '/access_management', &-> { slim :access_management }
  get '*favicon.ico', &-> { '' }
  get '/healthcheck', &-> { 'Healthy' }

end


