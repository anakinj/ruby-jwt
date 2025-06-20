# frozen_string_literal: true

RSpec.describe JWT::JWA::Ecdsa do
  describe '.curve_by_name' do
    subject { described_class.curve_by_name(curve_name) }

    context 'when secp256r1 is given' do
      let(:curve_name) { 'secp256r1' }
      it { is_expected.to eq(algorithm: 'ES256', digest: 'sha256') }
    end

    context 'when prime256v1 is given' do
      let(:curve_name) { 'prime256v1' }
      it { is_expected.to eq(algorithm: 'ES256', digest: 'sha256') }
    end

    context 'when secp521r1 is given' do
      let(:curve_name) { 'secp521r1' }
      it { is_expected.to eq(algorithm: 'ES512', digest: 'sha512') }
    end

    context 'when secp256k1 is given' do
      let(:curve_name) { 'secp256k1' }
      it { is_expected.to eq(algorithm: 'ES256K', digest: 'sha256') }
    end

    context 'when unknown is given' do
      let(:curve_name) { 'unknown' }
      it 'raises an error' do
        expect { subject }.to raise_error(JWT::UnsupportedEcdsaCurve)
      end
    end
  end

  let(:ecdsa_key) { test_pkey('ec256-private.pem') }
  let(:data) { 'test data' }
  let(:instance) { described_class.new('ES256', 'sha256') }
  let(:signature) { instance.sign(data: data, signing_key: ecdsa_key) }

  describe '#verify' do
    context 'when the verification key is valid' do
      it 'returns true for a valid signature' do
        expect(instance.verify(data: data, signature: signature, verification_key: ecdsa_key)).to be true
      end

      it 'returns false for an invalid signature' do
        expect(instance.verify(data: data, signature: 'invalid_signature', verification_key: ecdsa_key)).to be false
      end
    end

    context 'when verification results in a OpenSSL::PKey::PKeyError error' do
      it 'raises a JWT::VerificationError' do
        allow(ecdsa_key).to receive(:dsa_verify_asn1).and_raise(OpenSSL::PKey::PKeyError.new('Error'))
        expect do
          instance.verify(data: data, signature: '', verification_key: ecdsa_key)
        end.to raise_error(JWT::VerificationError, 'Signature verification raised')
      end
    end

    context 'when the verification key is not an OpenSSL::PKey::EC instance' do
      it 'raises a JWT::DecodeError' do
        expect do
          instance.verify(data: data, signature: '', verification_key: 'not_a_key')
        end.to raise_error(JWT::DecodeError, 'The given key is a String. It has to be an OpenSSL::PKey::EC instance')
      end
    end

    context 'when the verification key is a point' do
      it 'verifies the signature' do
        expect(ecdsa_key.public_key).to be_a(OpenSSL::PKey::EC::Point)
        expect(instance.verify(data: data, signature: signature, verification_key: ecdsa_key.public_key)).to be(true)
      end
    end
  end

  describe '#sign' do
    context 'when the signing key is valid' do
      it 'returns a valid signature' do
        expect(signature).to be_a(String)
        expect(signature.length).to be > 0
      end
    end

    context 'when the signing key is a public key' do
      it 'raises a JWT::DecodeError' do
        public_key = test_pkey('ec256-public.pem')
        expect do
          instance.sign(data: data, signing_key: public_key)
        end.to raise_error(JWT::EncodeError, 'The given key is not a private key')
      end
    end

    context 'when the signing key is not an OpenSSL::PKey::EC instance' do
      it 'raises a JWT::DecodeError' do
        expect do
          instance.sign(data: data, signing_key: 'not_a_key')
        end.to raise_error(JWT::EncodeError, 'The given key is a String. It has to be an OpenSSL::PKey::EC instance')
      end
    end

    context 'when the signing key is invalid' do
      it 'raises a JWT::DecodeError' do
        invalid_key = OpenSSL::PKey::EC.generate('sect571r1')
        expect do
          instance.sign(data: data, signing_key: invalid_key)
        end.to raise_error(JWT::DecodeError, "The ECDSA curve 'sect571r1' is not supported")
      end
    end
  end
end
