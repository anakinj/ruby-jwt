# frozen_string_literal: true

RSpec.describe ::JWT::Validators::ClaimsValidator do
  let(:base_payload) { { 'user_id' => 'some@user.tld' } }
  let(:string_payload) { 'beautyexperts_nbf_iat' }
  let(:options) { { leeway: 0 } }

  context '.verify_jti(payload, options)' do
    let(:payload) { base_payload.merge('jti' => 'some-random-uuid-or-whatever') }

    it 'must allow any jti when the verfy_jti key in the options is truthy but not a proc' do
      described_class.verify_jti(payload, options.merge(verify_jti: true))
    end

    it 'must raise JWT::InvalidJtiError when the jti is missing' do
      expect do
        described_class.verify_jti(base_payload, options)
      end.to raise_error JWT::InvalidJtiError, /missing/i
    end

    it 'must raise JWT::InvalidJtiError when the jti is an empty string' do
      expect do
        described_class.verify_jti(base_payload.merge('jti' => '   '), options)
      end.to raise_error JWT::InvalidJtiError, /missing/i
    end

    it 'must raise JWT::InvalidJtiError when verify_jti proc returns false' do
      expect do
        described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { false }))
      end.to raise_error JWT::InvalidJtiError, /invalid/i
    end

    it 'true proc should not raise JWT::InvalidJtiError' do
      described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { true }))
    end

    it 'it should not throw arguement error with 2 args' do
      expect do
        described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, _pl) {
          true
        }))
      end.to_not raise_error
    end
    it 'should have payload as second param in proc' do
      described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, pl) {
        expect(pl).to eq(payload)
      }))
    end
  end

  context '.verify_claims' do
    let(:fail_verifications_options) { { iss: 'mismatched-issuer', sub: 'some subject' } }
    let(:fail_verifications_payload) {
      {
        'exp' => (Time.now.to_i - 50),
        'jti' => '   ',
        'iss' => 'some-issuer',
        'nbf' => (Time.now.to_i + 50),
        'iat' => 'not a number',
        'sub' => 'not-a-match'
      }
    }

    %w[verify_jti].each do |method|
      let(:payload) { base_payload.merge(fail_verifications_payload) }
      it "must skip verification when #{method} option is set to false" do
        described_class.verify_claims(payload, options.merge(method => false))
      end

      it "must raise error when #{method} option is set to true" do
        expect do
          described_class.verify_claims(payload, options.merge(method => true).merge(fail_verifications_options))
        end.to raise_error JWT::DecodeError
      end
    end
  end
end
