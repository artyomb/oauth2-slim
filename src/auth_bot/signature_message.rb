# frozen_string_literal: true

module AuthBot
  # Builds the exact message covered by the bot's Ed25519 signature.
  module SignatureMessage
    module_function

    def build(scope:, login:, role: nil, time: Time.now.to_i)
      fields = [scope, time, login]
      normalized_role = normalize_role(role)
      fields << normalized_role if normalized_role
      fields.join('|')
    end

    def normalize_role(role)
      value = role.to_s.strip
      value unless value.empty?
    end
  end
end
