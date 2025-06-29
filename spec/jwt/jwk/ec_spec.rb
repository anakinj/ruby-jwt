# frozen_string_literal: true

RSpec.describe JWT::JWK::EC do
  let(:ec_key) { test_pkey('ec384-private.pem') }

  describe '.new' do
    subject { described_class.new(keypair) }

    context 'when a keypair with both keys given' do
      let(:keypair) { ec_key }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq true
      end
    end

    context 'when a keypair with only public key is given' do
      let(:keypair) { test_pkey('ec256-public.pem') }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
      end
    end

    context 'when a number is given' do
      let(:keypair) { 1234 }
      it 'raises an argument error' do
        expect { subject }.to raise_error(ArgumentError, 'key must be of type OpenSSL::PKey::EC or Hash with key parameters')
      end
    end

    context 'when EC with unsupported curve is given' do
      let(:keypair) { OpenSSL::PKey::EC.generate('prime239v2') }
      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "Unsupported curve 'prime239v2'")
      end
    end
  end

  describe '#keypair' do
    subject(:jwk) { described_class.new(ec_key) }

    it 'returns the key' do
      expect(jwk.keypair).to eq(ec_key)
    end
  end

  describe '#public_key' do
    subject(:jwk) { described_class.new(ec_key) }

    it 'returns the key' do
      expect(jwk.public_key).to eq(ec_key)
    end
  end

  describe '#export' do
    let(:kid) { nil }
    subject { described_class.new(keypair, kid).export }

    context 'when keypair with private key is exported' do
      let(:keypair) { ec_key }
      it 'returns a hash with the both parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :x, :y)

        # Exported keys do not currently include private key info,
        # event if the in-memory key had that information.  This is
        # done to match the traditional behavior of RSA JWKs.
        ## expect(subject).to include(:d)
      end
    end

    context 'when keypair with public key is exported' do
      let(:keypair) { test_pkey('ec256-public.pem') }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :x, :y)

        # Don't include private `d` if not explicitly requested.
        expect(subject).not_to include(:d)
      end

      context 'when a custom "kid" is provided' do
        let(:kid) { 'custom_key_identifier' }
        it 'exports it' do
          expect(subject[:kid]).to eq 'custom_key_identifier'
        end
      end
    end

    context 'when private key is requested' do
      subject { described_class.new(keypair).export(include_private: true) }
      let(:keypair) { ec_key }
      it 'returns a hash with the both parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :x, :y)

        # `d` is the private part.
        expect(subject).to include(:d)
      end
    end

    context 'when a common parameter is given' do
      let(:parameters) { { use: 'sig' } }
      let(:keypair) { ec_key }
      subject { described_class.new(keypair, parameters).export }
      it 'returns a hash including the common parameter' do
        expect(subject).to include(:use)
      end
    end
  end

  describe '#verify' do
    let(:data) { 'data_to_sign' }
    let(:signature) { jwk.sign(data: data) }

    context 'when jwk is missing the alg parameter' do
      let(:jwk) { described_class.new(ec_key) }

      context 'when the signature is valid' do
        it 'returns true' do
          expect(jwk.verify(data: data, signature: signature)).to be(true)
        end
      end
    end

    context 'when jwk has alg parameter' do
      let(:jwk) { described_class.new(ec_key, alg: 'ES384') }

      context 'when the signature is valid' do
        it 'returns true' do
          expect(jwk.verify(data: data, signature: signature)).to be(true)
        end
      end

      context 'when the signature is invalid' do
        it 'returns false' do
          expect(jwk.verify(data: data, signature: 'invalid')).to be(false)
        end
      end
    end

    context 'when the jwk has an invalid alg header' do
      let(:rsa) { described_class.new(ec_key, alg: 'INVALID') }
      it 'raises JWT::VerificationError' do
        expect { rsa.verify(data: data, signature: 'signature') }.to raise_error(JWT::VerificationError, 'Algorithm not supported')
      end
    end

    context 'when the jwk has none as the alg parameter' do
      let(:rsa) { described_class.new(ec_key, alg: 'none') }
      it 'raises JWT::JWKError' do
        expect { rsa.verify(data: data, signature: 'signature') }.to raise_error(JWT::JWKError, 'none algorithm usage not supported via JWK')
      end
    end

    context 'when the jwk has HS256 as the alg parameter' do
      let(:rsa) { described_class.new(ec_key, alg: 'HS256') }
      it 'raises JWT::DecodeError' do
        expect { rsa.verify(data: data, signature: 'signature') }.to raise_error(JWT::DecodeError, 'HMAC key expected to be a String')
      end
    end
  end

  describe '.to_openssl_curve' do
    context 'when a valid curve name is given' do
      it 'returns the corresponding OpenSSL curve name' do
        expect(JWT::JWK::EC.to_openssl_curve('P-256')).to eq('prime256v1')
        expect(JWT::JWK::EC.to_openssl_curve('P-384')).to eq('secp384r1')
        expect(JWT::JWK::EC.to_openssl_curve('P-521')).to eq('secp521r1')
        expect(JWT::JWK::EC.to_openssl_curve('P-256K')).to eq('secp256k1')
      end
    end
    context 'when an invalid curve name is given' do
      it 'raises an error' do
        expect { JWT::JWK::EC.to_openssl_curve('invalid-curve') }.to raise_error(JWT::JWKError, 'Invalid curve provided')
      end
    end
  end

  describe '.import' do
    subject { described_class.import(params) }
    let(:include_private) { false }
    let(:exported_key) { described_class.new(keypair).export(include_private: include_private) }

    %w[P-256 P-384 P-521 P-256K].each do |crv|
      context "when crv=#{crv}" do
        let(:openssl_curve) { JWT::JWK::EC.to_openssl_curve(crv) }
        let(:ec_key) { OpenSSL::PKey::EC.generate(openssl_curve) }

        context 'when keypair is private' do
          let(:include_private) { true }
          let(:keypair) { ec_key }
          let(:params) { exported_key }

          it 'returns a private key' do
            expect(subject.private?).to eq true
            expect(subject).to be_a described_class

            # Regular export returns only the non-private parts.
            public_only = exported_key.reject { |k, _v| k == :d }
            expect(subject.export).to eq(public_only)

            # Private export returns the original input.
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
        end

        context 'when keypair is public' do
          context 'returns a public key' do
            let(:keypair) { test_pkey('ec256-public.pem') }
            let(:params) { exported_key }

            it 'returns a hash with the public parts of the key' do
              expect(subject).to be_a described_class
              expect(subject.private?).to eq false
              expect(subject.export).to eq(exported_key)
            end
          end
        end
      end

      context 'with missing 0-byte at the start of EC coordinates' do
        let(:example_keysets) do
          [
            '{"kty":"EC","crv":"P-256","x":"0Nv5IKAlkvXuAKmOmFgmrwXKR7qGePOzu_7RXg5msw","y":"FqnPSNutcjfvXNlufwb7nLJuUEnBkbMdZ3P79nY9c3k"}',
            '{"kty":"EC","crv":"P-256","x":"xGjPg-7meZamM_yfkGeBUB2eJ5c82Y8vQdXwi5cVGw","y":"9FwKAuJacVyEy71yoVn1u1ETsQoiwF7QfkfXURGxg14"}',
            '{"kty":"EC","crv":"P-256","x":"yTvy0bwt5s29mIg1DMq-IjZH4pDgZIN9keEEaSuWZhk","y":"a0nrmd8qz8jpZDgpY82Rgv3vZ5xiJuiAoMIuRlGnaw"}',
            '{"kty":"EC","crv":"P-256","x":"yJen7AW4lLUTMH4luDj0wlMNSGCuOBB5R-ZoxlAU_g","y":"aMbA-M6ORHePSatiPVz_Pzu7z2XRnKMzK-HIscpfud8"}',
            '{"kty":"EC","crv":"P-256","x":"p_D00Z1ydC7mBIpSKPUUrzVzY9Fr5NMhhGfnf4P9guw","y":"lCqM3B_s04uhm7_91oycBvoWzuQWJCbMoZc46uqHXA"}',
            '{"kty":"EC","crv":"P-256","x":"hKS-vxV1bvfZ2xOuHv6Qt3lmHIiArTnhWac31kXw3w","y":"f_UWjrTpmq_oTdfss7YJ-9dEiYw_JC90kwAE-y0Yu-w"}',
            '{"kty":"EC","crv":"P-256","x":"3W22hN16OJN1XPpUQuCxtwoBRlf-wGyBNIihQiTmSdI","y":"eUaveaPQ4CpyfY7sfCqEF1DCOoxHdMpPHW15BmUF0w"}',
            '{"kty":"EC","crv":"P-256","x":"oq_00cGL3SxUZTA-JvcXALhfQya7elFuC7jcJScN7Bs","y":"1nNPIinv_gQiwStfx7vqs7Vt_MSyzoQDy9sCnZlFfg"}',
            '{"crv":"P-521","kty":"EC","x":"AMNQr/q+YGv4GfkEjrXH2N0+hnGes4cCqahJlV39m3aJpqSK+uiAvkRE5SDm2bZBc3YHGzhDzfMTUpnvXwjugUQP","y":"fIwouWsnp44Fjh2gBmO8ZafnpXZwLOCoaT5itu/Q4Z6j3duRfqmDsqyxZueDA3Gaac2LkbWGplT7mg4j7vCuGsw="}'
          ]
        end

        it 'prepends a 0-byte to either X or Y coordinate so that the keys decode correctly' do
          example_keysets.each do |keyset_json|
            jwk = described_class.import(JSON.parse(keyset_json))
            expect(jwk).to be_kind_of(JWT::JWK::EC)
          end
        end
      end
    end
  end
end
