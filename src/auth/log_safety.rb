require 'rack/utils'
require 'uri'

module LogSafety
  REDACTED = '[FILTERED]'
  SENSITIVE_KEY_PATTERNS = [
    /authorization/,
    /cookie/,
    /password|passwd|pwd/,
    /secret/,
    /token/,
    /\Acode\z/,
    /\Astate\z/,
    /signing.*key|private.*key|\Akey\z/
  ].freeze

  class << self
    def redact_hash(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, item), result|
          result[key] = sensitive_key?(key) ? REDACTED : redact_hash(item)
        end
      when Array
        value.map { |item| redact_hash(item) }
      when String
        redact_text(value)
      else
        value
      end
    end

    def redact_url(value)
      uri = URI.parse(value.to_s)
      return value if uri.query.to_s.empty?

      uri.query = Rack::Utils.build_nested_query(redact_hash(Rack::Utils.parse_nested_query(uri.query)))
      uri.to_s
    rescue URI::InvalidURIError
      redact_text(value)
    end

    def redact_query_string(value)
      Rack::Utils.build_nested_query(redact_hash(Rack::Utils.parse_nested_query(value.to_s)))
    rescue Rack::Utils::ParameterTypeError, Rack::QueryParser::ParamsTooDeepError
      redact_text(value)
    end

    def redact_text(value)
      text = value.to_s.dup
      text.gsub!(/((?:access_token|refresh_token|id_token|client_secret|password|token|secret|code|state)=)[^&\s]+/i, "\\1#{REDACTED}")
      text.gsub!(/(Bearer\s+)[A-Za-z0-9._~+\/=-]+/i, "\\1#{REDACTED}")
      text.gsub!(/((?:Authorization|Cookie|Set-Cookie):\s*)[^\n]+/i, "\\1#{REDACTED}")
      text
    end

    def exception_message(error)
      "#{error.class}: #{redact_text(error.message)}"
    end

    def request_log(env)
      {
        method: env['REQUEST_METHOD'],
        path: env['PATH_INFO'] || env['REQUEST_PATH'],
        request_uri: redact_url(env['REQUEST_URI'].to_s),
        query_string: redact_query_string(env['QUERY_STRING'].to_s)
      }.reject { |_, value| value.to_s.empty? }
    end

    def install_stack_service_base_header_logger
      return unless defined?(RackHelpers)

      # Override unsafe upstream request/response header logging for this auth service.
      logger = Class.new do
        def initialize(app, *)
          @app = app
        end

        def call(env)
          LOGGER.info(LogSafety.request_log(env)) if defined?(LOGGER)
          status, headers, body = @app.call(env)
          LOGGER.error("Request failed with HTTP #{status.to_i}") if defined?(LOGGER) && status.to_i >= 500
          [status, headers, body]
        end
      end

      RackHelpers.send(:remove_const, :HeadersLogger) if RackHelpers.const_defined?(:HeadersLogger, false)
      RackHelpers.const_set(:HeadersLogger, logger)
    end

    private

    def sensitive_key?(key)
      normalized = key.to_s.downcase.tr('-', '_')
      SENSITIVE_KEY_PATTERNS.any? { |pattern| normalized.match?(pattern) }
    end
  end
end
