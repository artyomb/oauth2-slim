# frozen_string_literal: true

require 'securerandom'
require 'uri'

AUTH_CODES = {} unless defined?(AUTH_CODES) # rubocop:disable Style/MutableConstant

# Shared OAuth/OIDC authorization request and one-time code handling.
module AuthorizationCode
  AUTHORIZATION_REQUEST_FIELDS = %i[
    client_id redirect_uri response_type scope state nonce
  ].freeze
  AUTH_CODE_IDENTITY_FIELDS = %i[uid login name role org email].freeze
  AUTH_CODE_TTL = 30

  def authorization_request_context
    AUTHORIZATION_REQUEST_FIELDS.each_with_object({}) do |field, context|
      value = params[field]
      context[field] = value unless value.nil?
    end
  end

  def authorization_form_fields(context)
    context.slice(*AUTHORIZATION_REQUEST_FIELDS)
  end

  def authorization_code_identity(grant)
    grant.slice(*AUTH_CODE_IDENTITY_FIELDS)
  end

  def clear_authorization_codes
    oldest = Time.now.to_i - AUTH_CODE_TTL
    AUTH_CODES.delete_if { |_code, grant| grant[:time].to_i < oldest }
  end

  def clear_codes = clear_authorization_codes

  def create_authorization_code(identity:, auth_scope:, context:)
    clear_authorization_codes
    code = SecureRandom.hex(16)
    identity = identity.transform_keys(&:to_sym).slice(*AUTH_CODE_IDENTITY_FIELDS)

    AUTH_CODES[code] = {
      scope: auth_scope,
      requested_scope: context[:scope],
      client_id: context[:client_id],
      redirect_uri: context[:redirect_uri].to_s,
      nonce: context[:nonce],
      time: Time.now.to_i,
      **identity
    }.compact

    code
  end

  def consume_authorization_code(code)
    clear_authorization_codes
    AUTH_CODES.delete(code.to_s)
  end

  def authorization_callback_uri(context, code)
    uri = URI.parse(context.fetch(:redirect_uri).to_s)
    query = URI.decode_www_form(uri.query.to_s)
    query.reject! { |key, _value| %w[code state].include?(key) }
    query << ['code', code]
    query << ['state', context[:state]] unless context[:state].to_s.empty?
    uri.query = URI.encode_www_form(query)
    uri.to_s
  end

  def redirect_with_authorization_code(identity:, auth_scope:, context:)
    code = create_authorization_code(identity:, auth_scope:, context:)
    redirect authorization_callback_uri(context, code)
  end
end
