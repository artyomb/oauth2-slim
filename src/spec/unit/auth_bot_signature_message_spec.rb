# frozen_string_literal: true

require_relative '../spec_helper'
require_relative '../../auth_bot/signature_message'

RSpec.describe AuthBot::SignatureMessage do
  describe '.build' do
    it 'keeps the legacy signed message when no role is configured' do
      message = described_class.build(scope: 'mayan.example.com', login: 'alice', time: 123)

      expect(message).to eq('mayan.example.com|123|alice')
    end

    it 'keeps the legacy signed message when the role column is empty' do
      message = described_class.build(scope: 'mayan.example.com', login: 'alice', role: '  ', time: 123)

      expect(message).to eq('mayan.example.com|123|alice')
    end

    it 'adds an explicitly configured role to the signed message' do
      message = described_class.build(scope: 'mayan.example.com', login: 'alice', role: 'admin', time: 123)

      expect(message).to eq('mayan.example.com|123|alice|admin')
    end
  end

  describe '.normalize_role' do
    it 'returns only a non-empty configured role' do
      expect(described_class.normalize_role(nil)).to be_nil
      expect(described_class.normalize_role('  ')).to be_nil
      expect(described_class.normalize_role(' admin ')).to eq('admin')
    end
  end
end
