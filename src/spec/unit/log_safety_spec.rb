require_relative "../spec_helper"
require_relative "../../auth/log_safety"

RSpec.describe LogSafety do
  class CaptureLogger
    attr_reader :messages

    def initialize
      @messages = []
    end

    def info(message)
      @messages << message.inspect
    end

    def error(message)
      @messages << message.inspect
    end
  end

  describe ".redact_hash" do
    it "redacts nested sensitive keys" do
      redacted = described_class.redact_hash(
        "Authorization" => "Bearer abc",
        "profile" => { "name" => "alice", "code" => "secret-code" },
        "items" => [{ "refresh_token" => "secret-refresh" }]
      )

      expect(redacted["Authorization"]).to eq(described_class::REDACTED)
      expect(redacted["profile"]["name"]).to eq("alice")
      expect(redacted["profile"]["code"]).to eq(described_class::REDACTED)
      expect(redacted["items"][0]["refresh_token"]).to eq(described_class::REDACTED)
    end
  end

  describe ".redact_url" do
    it "redacts sensitive URL query values including nested URL values" do
      redacted = described_class.redact_url(
        "https://auth.test/callback?code=abc&state=xyz&scope=openid&client_secret=top&redirect_uri=https%3A%2F%2Fapp.test%2Fcb%3Fcode%3Dnested"
      )

      expect(redacted).not_to include("abc")
      expect(redacted).not_to include("xyz")
      expect(redacted).not_to include("top")
      expect(redacted).not_to include("nested")
      expect(redacted).to include("scope=openid")
    end
  end

  describe ".redact_text" do
    it "redacts free-text secrets" do
      redacted = described_class.redact_text("Authorization: Bearer token123 client_secret=top Cookie: auth_token=cookie123")

      expect(redacted).not_to include("token123")
      expect(redacted).not_to include("top")
      expect(redacted).not_to include("cookie123")
    end
  end

  describe ".install_stack_service_base_header_logger" do
    it "does not log request headers, response cookies, or body content" do
      with_test_logger do |logger_capture|
        described_class.install_stack_service_base_header_logger
        app = ->(_env) { [500, { "Set-Cookie" => "auth_token=response-secret" }, ["body token=body-secret"]] }
        logger = RackHelpers::HeadersLogger.new(app)

        logger.call(
          "REQUEST_METHOD" => "GET",
          "PATH_INFO" => "/auth",
          "REQUEST_URI" => "/auth?code=raw-code&state=raw-state&scope=openid",
          "QUERY_STRING" => "code=raw-code&state=raw-state&scope=openid",
          "HTTP_AUTHORIZATION" => "Bearer request-secret",
          "HTTP_COOKIE" => "auth_token=request-cookie"
        )

        output = logger_capture.messages.join("\n")
        expect(output).not_to include("raw-code")
        expect(output).not_to include("raw-state")
        expect(output).not_to include("request-secret")
        expect(output).not_to include("request-cookie")
        expect(output).not_to include("response-secret")
        expect(output).not_to include("body-secret")
        expect(output).to include("scope=openid")
        expect(output).to include("HTTP 500")
      end
    end
  end

  def with_test_logger
    logger_was_defined = Object.const_defined?(:LOGGER)
    previous_logger = LOGGER if logger_was_defined
    Object.send(:remove_const, :LOGGER) if logger_was_defined
    logger_capture = CaptureLogger.new
    Object.const_set(:LOGGER, logger_capture)

    rack_helpers_was_defined = Object.const_defined?(:RackHelpers)
    Object.const_set(:RackHelpers, Module.new) unless rack_helpers_was_defined

    yield logger_capture
  ensure
    Object.send(:remove_const, :LOGGER)
    Object.const_set(:LOGGER, previous_logger) if logger_was_defined
    Object.send(:remove_const, :RackHelpers) unless rack_helpers_was_defined
  end
end
