# frozen_string_literal: true

require 'json'

module Authorization
  class Error < StandardError
    attr_reader :status, :code, :fields, :current_revision

    def initialize(message, status: 422, code: 'invalid_input', fields: {}, current_revision: nil)
      super(message)
      @status, @code, @fields, @current_revision = status, code, fields, current_revision
    end
  end

  class Validation
    FIELDS = %w[name description resource_type actions effect active priority definition schema_version].freeze
    DEFAULTS = { 'description' => '', 'active' => false, 'priority' => 0, 'schema_version' => 1 }.freeze

    def self.max_bytes = Integer(ENV.fetch('POLICY_MAX_PAYLOAD_BYTES', '262144'))
    def self.max_depth = Integer(ENV.fetch('POLICY_MAX_DEFINITION_DEPTH', '32'))

    def self.policy(input, partial: false)
      raise Error.new('Expected a JSON object', status: 400) unless input.is_a?(Hash)

      unknown = input.keys - FIELDS - (partial ? ['expected_revision'] : [])
      raise Error.new("Unknown fields: #{unknown.join(', ')}") unless unknown.empty?

      data = partial ? input.reject { |key, _| key == 'expected_revision' } : DEFAULTS.merge(input)
      errors = {}
      %w[name resource_type].each do |key|
        next if partial && !data.key?(key)

        value = data[key]
        errors[key] = 'Must be a nonempty string of at most 200 characters' unless value.is_a?(String) && !value.strip.empty? && value.length <= 200
      end
      if data.key?('description') && (!data['description'].is_a?(String) || data['description'].length > 4000)
        errors['description'] = 'Must be a string of at most 4000 characters'
      end
      { 'effect' => %w[allow deny], 'active' => [true, false], 'schema_version' => [1] }.each do |key, values|
        next if partial && !data.key?(key)

        errors[key] = "Must be one of: #{values.join(', ')}" unless values.include?(data[key])
      end
      if data.key?('schema_version') && !data['schema_version'].is_a?(Integer)
        errors['schema_version'] = 'Must be the integer 1'
      end
      if data.key?('priority') && !(data['priority'].is_a?(Numeric) && data['priority'].finite? && data['priority'].to_f.finite?)
        errors['priority'] = 'Must be a finite number'
      end
      if !partial || data.key?('actions')
        actions = data['actions']
        valid = actions.is_a?(Array) && actions.length.between?(1, 100) && actions.all? { |value| value.is_a?(String) && !value.strip.empty? && value.length <= 200 }
        errors['actions'] = 'Must contain between 1 and 100 nonempty action names, each at most 200 characters' unless valid
        data['actions'] = actions.uniq.sort if valid
      end
      if !partial || data.key?('definition')
        errors['definition'] = 'Must be a JSON object' unless data['definition'].is_a?(Hash)
        if data['definition'].is_a?(Hash)
          begin
            JSON.generate(data['definition'], max_nesting: max_depth)
          rescue JSON::NestingError, JSON::GeneratorError
            errors['definition'] = "Must be valid JSON with at most #{max_depth} nested levels"
          end
        end
      end
      errors['body'] = 'JSON strings cannot contain a null character' if null_character?(data)
      raise Error.new('Policy validation failed', fields: errors) unless errors.empty?
      raise Error.new("Policy must not exceed #{max_bytes} bytes", fields: { body: 'Payload too large' }) if JSON.generate(data).bytesize > max_bytes

      data.transform_keys(&:to_sym)
    end

    def self.null_character?(value)
      case value
      when String then value.include?("\u0000")
      when Hash then value.any? { |key, item| null_character?(key) || null_character?(item) }
      when Array then value.any? { |item| null_character?(item) }
      else false
      end
    end
    private_class_method :null_character?

    def self.id(value)
      text = value.to_s
      raise Error.new('Invalid identifier', status: 400) unless text.match?(/\A[1-9]\d*\z/) && text.to_i <= 2_147_483_647

      text.to_i
    end

    def self.revision(input)
      value = input['expected_revision']
      raise Error.new('expected_revision must be a positive integer', status: 400, fields: { expected_revision: 'Required positive integer' }) unless value.is_a?(Integer) && value.positive?

      value
    end

    def self.selector(value, name)
      raise Error.new("#{name} must be a nonempty string of at most 200 characters", status: 400, fields: { name => 'Required nonempty string' }) unless value.is_a?(String) && !value.strip.empty? && value.length <= 200

      value
    end

    def self.pagination(params)
      limit = params.fetch('limit', '25').to_s
      offset = params.fetch('offset', '0').to_s
      valid = limit.match?(/\A\d+\z/) && offset.match?(/\A\d+\z/) && limit.to_i.between?(1, 100) && offset.to_i <= 2_147_483_647
      raise Error.new('limit must be 1–100 and offset must be nonnegative', status: 400) unless valid

      { limit: limit.to_i, offset: offset.to_i }
    end
  end
end
