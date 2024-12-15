#!/usr/bin/env ruby
require_relative 'logging'
require_relative 'otlp'
require_relative 'helpers'
require_relative 'config.rb'
require_relative 'src/server'

# disable logging for Async::IO::Socket, Falcon::Server
Console.logger.enable Class, 3
# Console.logger.enable Falcon::Server, 3

otel_initialize

server = Rack::Builder.new do
  # if defined? OpenTelemetry::Instrumentation::Rack::Middlewares::TracerMiddleware
  #   use OpenTelemetry::Instrumentation::Rack::Middlewares::TracerMiddleware
  # end

  use (Class.new do
    def initialize(app, *opts) = (@app = app; @opts = opts)
    def call(env)
      request_headers = env.select { |k, _| k.start_with? 'HTTP_' }
      request_body = env['rack.input'].read

      response_code, response_headers, response_body = @app.call(env)
      response_body = response_body.read if response_body.respond_to? :read
      otl_span( :Request, {request_headers: , request_body:, response_code:, response_headers: , response_body: }) {}
      [response_code, response_headers, response_body]
    end
  end)

  run SinatraSrv
end

run server