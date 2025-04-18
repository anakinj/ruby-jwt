# frozen_string_literal: true

RSpec.describe JWT::JWK::HMAC do
  let(:hmac_key) { 'secret-key' }
  let(:key) { hmac_key }
  subject(:jwk) { described_class.new(key) }

  describe '.new' do
    context 'when a secret key given' do
      it 'creates an instance of the class' do
        expect(jwk).to be_a described_class
        expect(jwk.private?).to eq true
      end
    end

    context 'when key is a number' do
      let(:key) { 123 }
      it 'raises an ArgumentError' do
        expect { jwk }.to raise_error(ArgumentError, 'key must be of type String or Hash with key parameters')
      end
    end
  end

  describe '#keypair' do
    it 'returns a string' do
      expect(jwk.keypair).to eq(key)
    end
  end

  describe '#export' do
    let(:kid) { nil }

    context 'when key is exported' do
      let(:key) { hmac_key }
      subject { described_class.new(key, kid).export }
      it 'returns a hash with the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid)
      end
    end

    context 'when key is exported with private key' do
      let(:key) { hmac_key }
      subject { described_class.new(key, kid).export(include_private: true) }
      it 'returns a hash with the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :k)
      end
    end
  end

  describe '.import' do
    subject { described_class.import(params) }
    let(:exported_key) { described_class.new(key).export(include_private: true) }

    context 'when secret key is given' do
      let(:key) { hmac_key }
      let(:params) { exported_key }

      it 'returns a key' do
        expect(subject).to be_a described_class
        expect(subject.export(include_private: true)).to eq(exported_key)
      end

      context 'with a custom "kid" value' do
        let(:exported_key) do
          super().merge(kid: 'custom_key_identifier')
        end
        it 'imports that "kid" value' do
          expect(subject.kid).to eq('custom_key_identifier')
        end
      end

      context 'with a common parameter' do
        let(:exported_key) do
          super().merge(use: 'sig')
        end
        it 'imports that common parameter' do
          expect(subject[:use]).to eq('sig')
        end
      end
    end

    context 'when example from RFC' do
      let(:params) { { kty: 'oct', k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow' } }

      it 'decodes the k' do
        expected_key = "\x03#5K+\x0F\xA5\xBC\x83~\x06ew{\xA6\x8FZ\xB3(\xE6\xF0T\xC9(\xA9\x0F\x84\xB2\xD2P.\xBF\xD3\xFBZ\x92\xD2\x06G\xEF\x96\x8A\xB4\xC3wb=\"=.!r\x05.O\b\xC0\xCD\x9A\xF5g\xD0\x80\xA3".dup.force_encoding('ASCII-8BIT')
        expect(subject.verify_key).to eq(expected_key)
      end
    end
  end

  describe '#[]=' do
    context 'when k is given' do
      it 'raises an error' do
        expect { jwk[:k] = 'new_secret' }.to raise_error(ArgumentError, 'cannot overwrite cryptographic key attributes')
      end
    end
  end

  describe '#==' do
    it 'is equal to itself' do
      other = jwk
      expect(jwk == other).to eq true
    end

    it 'is equal to a clone of itself' do
      other = jwk.clone
      expect(jwk == other).to eq true
    end

    it 'is not equal to nil' do
      other = nil
      expect(jwk == other).to eq false
    end

    it 'is not equal to boolean true' do
      other = true
      expect(jwk == other).to eq false
    end

    it 'is not equal to a non-key' do
      other = Object.new
      expect(jwk == other).to eq false
    end

    it 'is not equal to a different key' do
      other = described_class.new('other-key')
      expect(jwk == other).to eq false
    end
  end

  describe '#<=>' do
    it 'is equal to itself' do
      other = jwk
      expect(jwk <=> other).to eq 0
    end

    it 'is equal to a clone of itself' do
      other = jwk.clone
      expect(jwk <=> other).to eq 0
    end

    it 'is not comparable to nil' do
      other = nil
      expect(jwk <=> other).to eq nil
    end

    it 'is not comparable to boolean true' do
      other = true
      expect(jwk <=> other).to eq nil
    end

    it 'is not comparable to a non-key' do
      other = Object.new
      expect(jwk <=> other).to eq nil
    end

    it 'is not equal to a different key' do
      other = described_class.new('other-key')
      expect(jwk <=> other).not_to eq 0
    end
  end
end
