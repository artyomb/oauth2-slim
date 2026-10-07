# frozen_string_literal: true

require 'digest'
require_relative 'repository'

module Authorization
  class PolicyResolver
    def initialize(repository)
      @repository = repository
    end

    def resolve(subject_id, resource_type:, action:)
      resource_type = Validation.selector(resource_type, 'resource_type')
      action = Validation.selector(action, 'action')
      data = @repository.effective(subject_id, resource_type:, action:)
      result = { subject: { id: subject_id }, resource_type:, action:, complete: true, data: }
      result.merge(policy_set_version: Digest::SHA256.hexdigest(JSON.generate(canonical(result))))
    end

    private

    def canonical(value)
      case value
      when Hash then value.sort_by { |key, _| key.to_s }.to_h.transform_values { |item| canonical(item) }
      when Array then value.map { |item| canonical(item) }
      else value
      end
    end
  end
end
