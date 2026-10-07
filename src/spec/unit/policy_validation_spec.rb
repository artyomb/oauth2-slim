# frozen_string_literal: true

require_relative '../spec_helper'
require_relative '../../authorization/validation'
require_relative '../../authorization/same_origin'

RSpec.describe Authorization::Validation do
  let(:input) do
    { 'name' => 'Policy', 'type' => 'filter', 'resource_type' => 'resource',
      'actions' => ['read'], 'effect' => 'allow', 'definition' => { 'matrices' => [[[1.2, -4.5], [8, 2]]] } }
  end

  it 'defaults new policies to disabled and preserves their JSON body' do
    result = described_class.policy(input)
    expect(result).to include(active: false, schema_version: 1, definition: input['definition'])
  end

  it 'deduplicates actions without modifying definitions' do
    input['actions'] = ['b', 'a', 'b']
    expect(described_class.policy(input)[:actions]).to eq(%w[a b])
  end

  it 'rejects invalid metadata and non-object definitions' do
    { 'name' => '', 'resource_type' => '', 'actions' => [], 'effect' => 'maybe', 'active' => 'false',
      'priority' => '1', 'type' => 'unknown', 'schema_version' => 1.0, 'definition' => [] }.each do |field, value|
      expect { described_class.policy(input.merge(field => value)) }.to raise_error(Authorization::Error) { |e| expect(e.fields).to have_key(field) }
    end
  end

  it 'rejects excessive nesting and payloads' do
    nested = { 'value' => (1..40).reduce({}) { |value, _| { 'not' => value } } }
    expect { described_class.policy(input.merge('definition' => nested)) }.to raise_error(Authorization::Error)
    expect { described_class.policy(input.merge('definition' => { 'large' => 'x' * described_class.max_bytes })) }.to raise_error(Authorization::Error)
  end

  it 'rejects JSONB-incompatible strings and non-finite or overflowing numbers' do
    expect { described_class.policy(input.merge('definition' => { 'value' => "\u0000" })) }.to raise_error(Authorization::Error)
    expect { described_class.policy(input.merge('definition' => { 'value' => Float::INFINITY })) }.to raise_error(Authorization::Error)
    expect { described_class.policy(input.merge('priority' => 10**1000)) }.to raise_error(Authorization::Error)
  end

  it 'does not allow request control fields or IDs to become policy content' do
    expect { described_class.policy(input.merge('id' => 2)) }.to raise_error(Authorization::Error)
    expect(described_class.policy({ 'expected_revision' => 2, 'definition' => {} }, partial: true)).to eq(definition: {})
  end

  it 'requires an integer revision and bounded pagination' do
    [nil, 0, '1', 1.2].each { |value| expect { described_class.revision('expected_revision' => value) }.to raise_error(Authorization::Error) }
    expect { described_class.pagination('limit' => '101') }.to raise_error(Authorization::Error)
    expect { described_class.pagination('offset' => '-1') }.to raise_error(Authorization::Error)
  end

  it 'rejects selectors and IDs with unexpected types or contents' do
    expect { described_class.selector(['resource'], 'resource_type') }.to raise_error(Authorization::Error)
    %w[0 -1 42abc 9999999999999].each { |id| expect { described_class.id(id) }.to raise_error(Authorization::Error) }
  end
end

RSpec.describe Authorization::SameOrigin do
  it 'removes inherited credentialed CORS only from policy surfaces' do
    app = ->(_) { [200, { 'access-control-allow-origin' => 'https://attacker.test', 'Access-Control-Allow-Credentials' => 'true' }, ['ok']] }
    middleware = described_class.new(app)
    %w[/admin/policies /api/v1/me/policies /api/v1/admin/policies/1 /api/v1/admin/policy-users].each do |path|
      headers = middleware.call('PATH_INFO' => path)[1]
      expect(headers.keys.grep(/access-control/i)).to be_empty
      expect(headers['cache-control']).to eq('no-store')
    end
    expect(middleware.call('PATH_INFO' => '/auth')[1]).to have_key('access-control-allow-origin')
  end
end
