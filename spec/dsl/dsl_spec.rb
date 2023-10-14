# frozen_string_literal: true

RSpec.describe JWT::DSL do
  describe '.sign_and_encode' do
    context 'when algorithm is given as HS256' do
      subject(:defined_obj) do
        JWT.define do
          signing_algorithm 'HS256'
        end
      end

      it 'creates a valid HS256 token' do
        signature = defined_obj.sign_and_encode(payload: 'payload', signing_key: 'secret')
        expect(signature).to eq('eyJhbGciOiJIUzI1NiJ9.InBheWxvYWQi.xZ3HN7F1t9dBMbKCXa9pye1VW6wC2A7V93Pva5jpkpI')
      end
    end
  end
end
