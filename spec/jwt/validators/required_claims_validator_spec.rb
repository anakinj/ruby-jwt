# frozen_string_literal: true

RSpec.describe JWT::Validators::RequiredClaimsValidator do
  let(:payload) { { 'data' => 'value' } }

  subject(:validate!) { described_class.new(required_claims: required_claims).validate!(context: Struct.new(:payload).new(payload)) }

  context 'when payload is missing the required claim' do
    let(:required_claims) { ['exp'] }
    it 'raises JWT::MissingRequiredClaim' do
      expect { validate! }.to raise_error JWT::MissingRequiredClaim, 'Missing required claim exp'
    end
  end

  context 'when payload has the required claims' do
    let(:payload) { { 'exp' => 'exp', 'custom_claim' => true } }
    let(:required_claims) { ['exp', 'custom_claim'] }
    it 'passes validation' do
      validate!
    end
  end
end
