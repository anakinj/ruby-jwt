# frozen_string_literal: true

RSpec.describe JWT::Claims::Expiration do
  let(:payload) { { 'exp' => (Time.now.to_i + 5) } }
  let(:leeway) { 0 }

  subject(:validate!) { described_class.new(leeway: leeway).validate!(context: JWT::Claims::ValidationContext.new(payload: payload)) }

  context 'when token is expired' do
    let(:payload) { { 'exp' => (Time.now.to_i - 5) } }

    it 'must raise JWT::ExpiredSignature when the token has expired' do
      expect { validate! }.to(raise_error(JWT::ExpiredSignature))
    end
  end

  context 'when token is expired but some leeway is defined' do
    let(:payload) { { 'exp' => (Time.now.to_i - 5) } }
    let(:leeway) { 10 }

    it 'passes validation' do
      validate!
    end
  end

  context 'when token exp is set to current time' do
    let(:payload) { { 'exp' => Time.now.to_i } }

    it 'fails validation' do
      expect { validate! }.to(raise_error(JWT::ExpiredSignature))
    end
  end

  context 'when token is not a Hash' do
    let(:payload) { 'beautyexperts_nbf_iat' }
    it 'passes validation' do
      validate!
    end
  end
end
