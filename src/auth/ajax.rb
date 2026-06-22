require_relative 'log_safety'

module Ajax
  module Helpers
    class AJAX_Error < StandardError
      def initialize(e, response)
        LOGGER.error "AJAX error: #{LogSafety.exception_message(e)}" if defined?(LOGGER)
        @response = response
      end
      def to_json; @response.to_json end
    end
    #   rescue => e
    #     raise AJAX_Error.new(e, action: 'error', message: e.message)

    def self.included(base)
      # base.extend ClassMethods
      base.class_eval do
        def parse_data
          if @env['CONTENT_TYPE'] =~ /application\/json/
            body_str = request.body.read
            body_str.force_encoding 'utf-8'
            body_str.empty? ? {} : JSON.parse(body_str, symbolize_names: true)
          else
            params # rack.request.form_hash', 'rack.request.form_imput', 'rack.tempfile'
          end
        end

        def self.exception2halt(&block)
          proc do |**args|
            instance_exec **args, &block
          rescue AJAX_Error => e
            halt 403, e.to_json
          rescue => e
            LOGGER.error "AJAX request failed: #{LogSafety.exception_message(e)}" if defined?(LOGGER)
            halt 502, { result: 'failed', error: 'Internal server error' }.to_json
          end
        end

        def self.ajax_call(method, path, &block)
          send method, path, &exception2halt {
            content_type :json
            response = block.arity == 1 ? instance_exec(parse_data, &block) : instance_exec(&block)
            { result: 'successful', response: response }.to_json
          }
        end
      end
    end
  end
end
