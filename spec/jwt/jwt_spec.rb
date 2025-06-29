# frozen_string_literal: true

RSpec.describe JWT do
  let(:payload) { { 'user_id' => 'some@user.tld' } }

  let(:data) do
    {
      :empty_token => 'e30K.e30K.e30K',
      :empty_token_2_segment => 'e30K.e30K.',
      :invalid_header_token => 'W10.e30K.e30K',
      :secret => 'My$ecretK3y',
      :rsa_private => test_pkey('rsa-2048-private.pem'),
      :rsa_public => test_pkey('rsa-2048-public.pem'),
      :wrong_rsa_private => test_pkey('rsa-2048-wrong-public.pem'),
      :wrong_rsa_public => test_pkey('rsa-2048-wrong-public.pem'),
      'ES256_private' => test_pkey('ec256-private.pem'),
      'ES256_public' => test_pkey('ec256-public.pem'),
      'ES256_private_v2' => test_pkey('ec256-private-v2.pem'),
      'ES256_public_v2' => test_pkey('ec256-public-v2.pem'),
      'ES384_private' => test_pkey('ec384-private.pem'),
      'ES384_public' => test_pkey('ec384-public.pem'),
      'ES512_private' => test_pkey('ec512-private.pem'),
      'ES512_public' => test_pkey('ec512-public.pem'),
      'ES256K_private' => test_pkey('ec256k-private.pem'),
      'ES256K_public' => test_pkey('ec256k-public.pem'),
      'NONE' => 'eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.',
      'HS256' => 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.kWOVtIOpWcG7JnyJG0qOkTDbOy636XrrQhMm_8JrRQ8',
      'HS384' => 'eyJhbGciOiJIUzM4NCJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.VuV4j4A1HKhWxCNzEcwc9qVF3frrEu-BRLzvYPkbWO0LENRGy5dOiBQ34remM3XH',
      'HS512' => 'eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.8zNtCBTJIZTHpZ-BkhR-6sZY1K85Nm5YCKqV3AxRdsBJDt_RR-REH2db4T3Y0uQwNknhrCnZGvhNHrvhDwV1kA',
      'RS256' => 'eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.eSXvWP4GViiwUALj_-qTxU68I1oM0XjgDsCZBBUri2Ghh9d75QkVDoZ_v872GaqunN5A5xcnBK0-cOq-CR6OwibgJWfOt69GNzw5RrOfQ2mz3QI3NYEq080nF69h8BeqkiaXhI24Q51joEgfa9aj5Y-oitLAmtDPYTm7vTcdGufd6AwD3_3jajKBwkh0LPSeMtbe_5EyS94nFoEF9OQuhJYjUmp7agsBVa8FFEjVw5jEgVqkvERSj5hSY4nEiCAomdVxIKBfykyi0d12cgjhI7mBFwWkPku8XIPGZ7N8vpiSLdM68BnUqIK5qR7NAhtvT7iyLFgOqhZNUQ6Ret5VpQ',
      'RS384' => 'eyJhbGciOiJSUzM4NCJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.Sfgk56moPghtsjaP4so6tOy3I553mgwX-5gByMC6dX8lpeWgsxSeAd_K8IyO7u4lwYOL0DSftnqO1HEOuN1AKyBbDvaTXz3u2xNA2x4NYLdW4AZA6ritbYcKLO5BHTXw5ueMbtA1jjGXP0zI_aK2iJTMBmB8SCF88RYBUH01Tyf4PlLj98pGL-v3prZd6kZkIeRJ3326h04hslcB5HQKmgeBk24QNLIoIC-CD329HPjJ7TtGx01lj-ehTBnwVbBGzYFAyoalV5KgvL_MDOfWPr1OYHnR5s_Fm6_3Vg4u6lBljvHOrmv4Nfx7d8HLgbo8CwH4qn1wm6VQCtuDd-uhRg',
      'RS512' => 'eyJhbGciOiJSUzUxMiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.LIIAUEuCkGNdpYguOO5LoW4rZ7ED2POJrB0pmEAAchyTdIK4HKh1jcLxc6KyGwZv40njCgub3y72q6vcQTn7oD0zWFCVQRIDW1911Ii2hRNHuigiPUnrnZh1OQ6z65VZRU6GKs8omoBGU9vrClBU0ODqYE16KxYmE_0n4Xw2h3D_L1LF0IAOtDWKBRDa3QHwZRM9sHsHNsBuD5ye9KzDYN1YALXj64LBfA-DoCKfpVAm9NkRPOyzjR2X2C3TomOSJgqWIVHJucudKDDAZyEbO4RA5pI-UFYy1370p9bRajvtDyoBuLDCzoSkMyQ4L2DnLhx5CbWcnD7Cd3GUmnjjTA',
      'ES256' => '',
      'ES384' => '',
      'ES512' => '',
      'PS256' => '',
      'PS384' => '',
      'PS512' => ''
    }
  end

  context 'alg: NONE' do
    let(:alg) { 'none' }
    let(:encoded_token) { data['NONE'] }

    it 'should generate a valid token' do
      token = JWT.encode payload, nil, alg

      expect(token).to eq encoded_token
    end

    context 'decoding without verification' do
      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode encoded_token, nil, false

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end
    end

    context 'decoding with verification' do
      context 'without specifying the none algorithm' do
        it 'should fail to decode the token' do
          expect do
            JWT.decode encoded_token, nil, true
          end.to raise_error JWT::IncorrectAlgorithm
        end
      end

      context 'specifying the none algorithm' do
        context 'when the claims are valid' do
          it 'should decode the token' do
            jwt_payload, header = JWT.decode encoded_token, nil, true, { algorithms: 'none' }

            expect(header['alg']).to eq 'none'
            expect(jwt_payload).to eq payload
          end
        end

        context 'when the claims are invalid' do
          let(:encoded_token) { JWT.encode({ exp: 0 }, nil, 'none') }
          it 'should fail to decode the token' do
            expect do
              JWT.decode encoded_token, nil, true
            end.to raise_error JWT::DecodeError
          end
        end
      end
    end
  end

  %w[HS256 HS384 HS512].each do |alg|
    context "alg: #{alg}" do
      it 'should generate a valid token' do
        token = JWT.encode payload, data[:secret], alg

        expect(token).to eq data[alg]
      end

      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode data[alg], data[:secret], true, algorithm: alg

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'wrong secret should raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], 'wrong_secret', true, algorithm: alg
        end.to raise_error JWT::VerificationError
      end

      it 'wrong secret and verify = false should not raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], 'wrong_secret', false
        end.not_to raise_error
      end
    end
  end

  %w[RS256 RS384 RS512].each do |alg|
    context "alg: #{alg}" do
      it 'should generate a valid token' do
        token = JWT.encode payload, data[:rsa_private], alg

        expect(token).to eq data[alg]
      end

      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode data[alg], data[:rsa_public], true, algorithm: alg

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'should decode a valid token using algorithm hash string key' do
        jwt_payload, header = JWT.decode data[alg], data[:rsa_public], true, 'algorithm' => alg

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'wrong key should raise JWT::DecodeError' do
        key = test_pkey('rsa-2048-wrong-public.pem')

        expect do
          JWT.decode data[alg], key, true, algorithm: alg
        end.to raise_error JWT::DecodeError
      end

      it 'wrong key and verify = false should not raise JWT::DecodeError' do
        key = test_pkey('rsa-2048-wrong-public.pem')

        expect do
          JWT.decode data[alg], key, false
        end.not_to raise_error
      end
    end
  end

  %w[ES256 ES384 ES512 ES256K].each do |alg|
    before do
      skip 'OpenSSL gem missing RSA-PSS support' unless OpenSSL::PKey::RSA.method_defined?(:sign_pss)
    end

    context "alg: #{alg}" do
      before(:each) do
        data[alg] = JWT.encode(payload, data["#{alg}_private"], alg)
      end

      let(:wrong_key) { test_pkey('ec256-wrong-public.pem') }

      it 'should generate a valid token' do
        jwt_payload, header = JWT.decode data[alg], data["#{alg}_public"], true, algorithm: alg

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode data[alg], data["#{alg}_public"], true, algorithm: alg

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'wrong key should raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], wrong_key
        end.to raise_error JWT::DecodeError
      end

      it 'wrong key and verify = false should not raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], wrong_key, false
        end.not_to raise_error
      end
    end
  end

  %w[PS256 PS384 PS512].each do |alg|
    context "alg: #{alg}" do
      before(:each) do
        data[alg] = JWT.encode payload, data[:rsa_private], alg
      end

      let(:wrong_key) { data[:wrong_rsa_public] }

      it 'should generate a valid token' do
        token = data[alg]

        header, body, signature = token.split('.')

        expect(header).to eql(Base64.strict_encode64({ alg: alg }.to_json))
        expect(body).to   eql(Base64.strict_encode64(payload.to_json))

        # Validate signature is made of up header and body of JWT
        translated_alg  = alg.gsub('PS', 'sha')
        valid_signature = data[:rsa_public].verify_pss(
          translated_alg,
          JWT::Base64.url_decode(signature),
          [header, body].join('.'),
          salt_length: :auto,
          mgf1_hash: translated_alg
        )
        expect(valid_signature).to be true
      end

      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode data[alg], data[:rsa_public], true, algorithm: alg

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'wrong key should raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], wrong_key
        end.to raise_error JWT::DecodeError
      end

      it 'wrong key and verify = false should not raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], wrong_key, false
        end.not_to raise_error
      end
    end
  end

  context 'Invalid' do
    it 'algorithm should raise DecodeError' do
      expect do
        JWT.encode payload, 'secret', 'HS255'
      end.to raise_error JWT::EncodeError
    end

    it 'raises "No verification key available" error' do
      token = JWT.encode({}, 'foo')
      expect { JWT.decode(token, nil, true) }.to raise_error(JWT::DecodeError, 'No verification key available')
    end

    it 'ECDSA curve_name should raise JWT::IncorrectAlgorithm' do
      key = OpenSSL::PKey::EC.generate('secp256k1')

      expect do
        JWT.encode payload, key, 'ES256'
      end.to raise_error JWT::IncorrectAlgorithm

      token = JWT.encode payload, data['ES256_private'], 'ES256'

      expect do
        JWT.decode token, key
      end.to raise_error JWT::IncorrectAlgorithm
    end
  end

  context 'Verify' do
    context 'when key given as an array with multiple possible keys' do
      let(:payload) { { 'data' => 'data' } }
      let(:token)   { JWT.encode(payload, secret, 'HS256') }
      let(:secret)  { 'hmac_secret' }

      it 'should be able to verify signature when block returns multiple keys' do
        decoded_token = JWT.decode(token, nil, true, { algorithm: 'HS256' }) do
          ['not_the_secret', secret]
        end
        expect(decoded_token.first).to eq(payload)
      end

      it 'should be able to verify signature when multiple keys given as a parameter' do
        decoded_token = JWT.decode(token, ['not_the_secret', secret], true, { algorithm: 'HS256' })
        expect(decoded_token.first).to eq(payload)
      end

      it 'should fail if only invalid keys are given' do
        expect do
          JWT.decode(token, %w[not_the_secret not_the_secret_2], true, { algorithm: 'HS256' })
        end.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when encoded payload is used to extract key through find_key' do
      it 'should be able to find a key using the block passed to decode' do
        payload_data = { key: 'secret' }
        token = JWT.encode payload_data, data[:secret], 'HS256'

        expect do
          JWT.decode(token, nil, true, { algorithm: 'HS256' }) do |_headers, payload|
            data[payload['key'].to_sym]
          end
        end.not_to raise_error
      end

      it 'should be able to verify signature when block returns multiple keys' do
        iss = 'My_Awesome_Company'
        iss_payload = { data: 'data', iss: iss }

        secrets = { iss => ['hmac_secret2', data[:secret]] }

        token = JWT.encode iss_payload, data[:secret], 'HS256'

        expect do
          JWT.decode(token, nil, true, { iss: iss, verify_iss: true, algorithm: 'HS256' }) do |_headers, payload|
            secrets[payload['iss']]
          end
        end.not_to raise_error
      end

      it 'should be able to find a key using the block passed to decode with iss verification' do
        iss = 'My_Awesome_Company'
        iss_payload = { data: 'data', iss: iss }

        secrets = { iss => data[:secret] }

        token = JWT.encode iss_payload, data[:secret], 'HS256'

        expect do
          JWT.decode(token, nil, true, { iss: iss, verify_iss: true, algorithm: 'HS256' }) do |_headers, payload|
            secrets[payload['iss']]
          end
        end.not_to raise_error
      end

      it 'should be able to verify signature when block returns multiple keys with iss verification' do
        iss = 'My_Awesome_Company'
        iss_payload = { data: 'data', iss: iss }

        secrets = { iss => ['hmac_secret2', data[:secret]] }

        token = JWT.encode iss_payload, data[:secret], 'HS256'

        expect do
          JWT.decode(token, nil, true, { iss: iss, verify_iss: true, algorithm: 'HS256' }) do |_headers, payload|
            secrets[payload['iss']]
          end
        end.not_to raise_error
      end

      it 'should be able to find a key using a block with multiple issuers' do
        issuers = %w[My_Awesome_Company1 My_Awesome_Company2]
        iss_payload = { data: 'data', iss: issuers.first }

        secrets = { issuers.first => data[:secret], issuers.last => 'hmac_secret2' }

        token = JWT.encode iss_payload, data[:secret], 'HS256'

        expect do
          JWT.decode(token, nil, true, { iss: issuers, verify_iss: true, algorithm: 'HS256' }) do |_headers, payload|
            secrets[payload['iss']]
          end
        end.not_to raise_error
      end

      it 'should be able to verify signature when block returns multiple keys with multiple issuers' do
        issuers = %w[My_Awesome_Company1 My_Awesome_Company2]
        iss_payload = { data: 'data', iss: issuers.first }

        secrets = { issuers.first => [data[:secret], 'hmac_secret1'], issuers.last => 'hmac_secret2' }

        token = JWT.encode iss_payload, data[:secret], 'HS256'

        expect do
          JWT.decode(token, nil, true, { iss: issuers, verify_iss: true, algorithm: 'HS256' }) do |_headers, payload|
            secrets[payload['iss']]
          end
        end.not_to raise_error
      end
    end

    context 'algorithm' do
      it 'should raise JWT::IncorrectAlgorithm on mismatch' do
        token = JWT.encode payload, data[:secret], 'HS256'

        expect do
          JWT.decode token, data[:secret], true, algorithm: 'HS384'
        end.to raise_error JWT::IncorrectAlgorithm

        expect do
          JWT.decode token, data[:secret], true, algorithm: 'HS256'
        end.not_to raise_error
      end

      it 'should raise JWT::IncorrectAlgorithm on mismatch prior to kid public key network call' do
        token = JWT.encode payload, data[:rsa_private], 'RS256'

        expect do
          JWT.decode(token, nil, true, { algorithms: ['RS384'] }) do |_, _|
            # unsuccessful keyfinder public key network call here
          end
        end.to raise_error JWT::IncorrectAlgorithm

        expect do
          JWT.decode(token, nil, true, { 'algorithms' => ['RS384'] }) do |_, _|
            # unsuccessful keyfinder public key network call here
          end
        end.to raise_error JWT::IncorrectAlgorithm
      end

      it 'raises error when keyfinder does not find anything' do
        token = JWT.encode(payload, 'secret', 'HS256')

        expect do
          JWT.decode(token, nil, true, algorithm: 'HS256') do
            nil
          end
        end.to raise_error JWT::DecodeError, 'No verification key available'
      end

      it 'should raise JWT::IncorrectAlgorithm when algorithms array does not contain algorithm' do
        token = JWT.encode payload, data[:secret], 'HS512'

        expect do
          JWT.decode token, data[:secret], true, algorithms: ['HS384']
        end.to raise_error JWT::IncorrectAlgorithm

        expect do
          JWT.decode token, data[:secret], true, 'algorithms' => ['HS384']
        end.to raise_error JWT::IncorrectAlgorithm

        expect do
          JWT.decode token, data[:secret], true, algorithms: %w[HS512 HS384]
        end.not_to raise_error

        expect do
          JWT.decode token, data[:secret], true, 'algorithms' => %w[HS512 HS384]
        end.not_to raise_error
      end

      context 'no algorithm provided' do
        it 'should use the default decode algorithm' do
          token = JWT.encode payload, data[:rsa_public].to_s

          jwt_payload, header = JWT.decode token, data[:rsa_public].to_s

          expect(header['alg']).to eq 'HS256'
          expect(jwt_payload).to eq payload
        end
      end

      context 'token is missing algorithm' do
        it 'should raise JWT::IncorrectAlgorithm' do
          expect do
            JWT.decode data[:empty_token]
          end.to raise_error JWT::IncorrectAlgorithm
        end

        context 'invalid header format' do
          it 'should raise JWT::DecodeError' do
            expect do
              JWT.decode data[:invalid_header_token]
            end.to raise_error JWT::DecodeError
          end
        end

        context '2-segment token' do
          it 'should raise JWT::IncorrectAlgorithm' do
            expect do
              JWT.decode data[:empty_token_2_segment]
            end.to raise_error JWT::DecodeError
          end
        end
      end
    end

    context 'issuer claim' do
      let(:iss) { 'ruby-jwt-gem' }
      let(:invalid_token) { JWT.encode payload, data[:secret] }

      let(:token) do
        iss_payload = payload.merge(iss: iss)
        JWT.encode iss_payload, data[:secret]
      end

      it 'if verify_iss is set to false (default option) should not raise JWT::InvalidIssuerError' do
        expect do
          JWT.decode token, data[:secret], true, iss: iss, algorithm: 'HS256'
        end.not_to raise_error
      end

      context 'when verify_iss is set to true and no issues given' do
        it 'does not raise' do
          expect do
            JWT.decode(token, data[:secret], true, verify_iss: true, algorithm: 'HS256')
          end.not_to raise_error
        end
      end
    end

    context 'audience claim' do
      let(:token) { JWT.encode(payload, data[:secret]) }

      context 'when verify_aud is set to true and no audience given' do
        it 'does not raise' do
          expect do
            JWT.decode(token, data[:secret], true, verify_aud: true, algorithm: 'HS256')
          end.not_to raise_error
        end
      end
    end

    context 'claim verification order' do
      let(:token) { JWT.encode({ nbf: Time.now.to_i + 100 }, 'secret') }

      context 'when two claims are invalid' do
        it 'depends on the order of the parameters what error is raised' do
          expect { JWT.decode(token, 'secret', true, { verify_jti: true, verify_not_before: true }) }.to raise_error(JWT::ImmatureSignature, 'Signature nbf has not been reached')
        end
      end
    end
  end

  context 'a token with no segments' do
    it 'raises JWT::DecodeError' do
      expect { JWT.decode('ThisIsNotAValidJWTToken', nil, true) }.to raise_error(JWT::DecodeError, 'Not enough or too many segments')
    end
  end

  context 'a token with not enough segments' do
    it 'raises JWT::DecodeError' do
      token = JWT.encode('ThisIsNotAValidJWTToken', 'secret').split('.').slice(1, 2).join
      expect { JWT.decode(token, nil, true) }.to raise_error(JWT::DecodeError, 'Not enough or too many segments')
    end
  end

  context 'a token with not too many segments' do
    it 'raises JWT::DecodeError' do
      expect { JWT.decode('ThisIsNotAValidJWTToken.second.third.signature', nil, true) }.to raise_error(JWT::DecodeError, 'Not enough or too many segments')
    end
  end

  context 'a token with invalid Base64 segments' do
    it 'raises JWT::Base64DecodeError' do
      expect { JWT.decode('hello.there.world') }.to raise_error(JWT::Base64DecodeError, 'Invalid base64 encoding')
    end
  end

  context 'a token with two segments but does not require verifying' do
    it 'raises something else than "Not enough or too many segments"' do
      expect { JWT.decode('ThisIsNotAValidJWTToken.second', nil, false) }.to raise_error(JWT::Base64DecodeError, 'Invalid base64 encoding')
    end
  end

  it 'should not verify token even if the payload has claims' do
    head = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9'
    load = 'eyJ1c2VyX2lkIjo1NCwiZXhwIjoxNTA0MzkwODA0fQ'
    sign = 'Skpi6FfYMbZ-DwW9ocyRIosNMdPMAIWRLYxRO68GTQk'

    expect do
      JWT.decode([head, load, sign].join('.'), '', false)
    end.not_to raise_error
  end

  it 'should not raise InvalidPayload exception if payload is an array' do
    expect do
      JWT.encode(%w[my payload], 'secret')
    end.not_to raise_error
  end

  it 'should encode string payloads' do
    expect do
      JWT.encode 'Hello World', 'secret'
    end.not_to raise_error
  end

  context 'when the alg value is given as a header parameter' do
    it 'overrides the actual algorithm used' do
      headers = JSON.parse(JWT::Base64.url_decode(JWT.encode('Hello World', 'secret', 'HS256', { alg: 'HS123' }).split('.').first))
      expect(headers['alg']).to eq('HS123')
    end

    it 'should generate the same token' do
      expect(JWT.encode('Hello World', 'secret', 'HS256', { alg: 'HS256' })).to eq JWT.encode('Hello World', 'secret', 'HS256')
    end
  end

  context 'when hmac algorithm is used without secret key' do
    it 'encodes payload' do
      pending 'Different behaviour on OpenSSL 3.0 (https://github.com/openssl/openssl/issues/13089)' if JWT.openssl_3_hmac_empty_key_regression?
      payload = { a: 1, b: 'b' }

      token = JWT.encode(payload, '', 'HS256')

      expect do
        token_without_secret = JWT.encode(payload, nil, 'HS256')
        expect(token).to eq(token_without_secret)
      end.not_to raise_error
    end
  end

  context 'algorithm case insensitivity' do
    let(:payload) { { 'a' => 1, 'b' => 'b' } }

    it 'ignores algorithm casing during encode/decode' do
      enc = JWT.encode(payload, 'secret', 'hs256')
      expect(JWT.decode(enc, 'secret')).to eq([payload, { 'alg' => 'HS256' }])

      enc = JWT.encode(payload, data[:rsa_private], 'rs512')
      expect(JWT.decode(enc, data[:rsa_public], true, algorithm: 'RS512')).to eq([payload, { 'alg' => 'RS512' }])

      enc = JWT.encode(payload, data[:rsa_private], 'RS512')
      expect(JWT.decode(enc, data[:rsa_public], true, algorithm: 'rs512')).to eq([payload, { 'alg' => 'RS512' }])
    end

    it 'raises error for invalid algorithm' do
      expect do
        JWT.encode(payload, '', 'xyz')
      end.to raise_error(JWT::EncodeError)
    end
  end

  describe '::JWT.decode with verify_iat parameter' do
    let!(:time_now) { Time.now }
    let(:token)     { JWT.encode({ pay: 'load', iat: iat }, 'secret', 'HS256') }

    subject(:decoded_token) { JWT.decode(token, 'secret', true, verify_iat: true) }

    before { allow(Time).to receive(:now) { time_now } }

    context 'when iat is exactly the same as Time.now and iat is given as a float' do
      let(:iat) { time_now.to_f }
      it 'considers iat valid' do
        expect(decoded_token).to be_an(Array)
      end
    end

    context 'when iat is exactly the same as Time.now and iat is given as floored integer' do
      let(:iat) { time_now.to_f.floor }
      it 'considers iat valid' do
        expect(decoded_token).to be_an(Array)
      end
    end

    context 'when iat is 1 second before Time.now' do
      let(:iat) { time_now.to_i + 1 }
      it 'raises an error' do
        expect { decoded_token }.to raise_error(JWT::InvalidIatError, 'Invalid iat')
      end
    end
  end

  describe '::JWT.decode with x5c parameter' do
    let(:alg) { 'RS256' }
    let(:root_certificates) { [instance_double('OpenSSL::X509::Certificate')] }
    let(:key_finder) { instance_double('::JWT::X5cKeyFinder') }

    before do
      expect(JWT::X5cKeyFinder).to receive(:new).with(root_certificates, nil).and_return(key_finder)
      expect(key_finder).to receive(:from).and_return(data[:rsa_public])
    end
    subject(:decoded_token) { JWT.decode(data[alg], nil, true, algorithm: alg, x5c: { root_certificates: root_certificates }) }

    it 'calls X5cKeyFinder#from to verify the signature and return the payload' do
      jwt_payload, header = decoded_token

      expect(header['alg']).to eq alg
      expect(jwt_payload).to eq payload
    end
  end

  describe 'when keyfinder given with 1 argument' do
    let(:token) { JWT.encode(payload, 'HS256', 'HS256') }
    it 'decodes the token' do
      expect(JWT.decode(token, nil, true, algorithm: 'HS256') { |header| header['alg'] }).to include(payload)
    end
  end

  describe 'when keyfinder given with 2 arguments' do
    let(:token) { JWT.encode(payload, payload['user_id'], 'HS256') }
    it 'decodes the token' do
      expect(JWT.decode(token, nil, true, algorithm: 'HS256') { |_header, payload| payload['user_id'] }).to include(payload)
    end
  end

  describe 'when keyfinder given with 3 arguments' do
    let(:token) { JWT.encode(payload, 'HS256', 'HS256') }
    it 'decodes the token but does not pass the payload' do
      expect(JWT.decode(token, nil, true, algorithm: 'HS256') do |header, token_payload, nothing|
        expect(token_payload).to eq(nil) # This behaviour is not correct, the payload should be available in the keyfinder
        expect(nothing).to eq(nil)
        header['alg']
      end).to include(payload)
    end
  end

  describe 'when none token is and decoding without key and with verification' do
    let(:none_token) { JWT.encode(payload, nil, 'none') }
    it 'decodes the token' do
      expect(JWT.decode(none_token, nil, true, algorithms: 'none')).to eq([payload, { 'alg' => 'none' }])
    end
  end

  describe 'when none token is decoded with a key given' do
    let(:none_token) { JWT.encode(payload, nil, 'none') }
    it 'decodes the token' do
      expect(JWT.decode(none_token, 'key', true, algorithms: 'none')).to eq([payload, { 'alg' => 'none' }])
    end
  end

  describe 'when none token is decoded without verify' do
    let(:none_token) { JWT.encode(payload, nil, 'none') }
    it 'decodes the token' do
      expect(JWT.decode(none_token, 'key', false)).to eq([payload, { 'alg' => 'none' }])
    end
  end

  describe 'when token signed with nil and decoded with nil' do
    let(:no_key_token) { JWT.encode(payload, nil, 'HS512') }
    it 'raises JWT::DecodeError' do
      pending 'Different behaviour on OpenSSL 3.0 (https://github.com/openssl/openssl/issues/13089)' if JWT.openssl_3_hmac_empty_key_regression?
      expect { JWT.decode(no_key_token, nil, true, algorithms: 'HS512') }.to raise_error(JWT::DecodeError, 'No verification key available')
    end
  end

  context 'when token ends with a newline char' do
    let(:token) { "#{JWT.encode(payload, 'secret', 'HS256')}\n" }
    it 'raises an error' do
      expect { JWT.decode(token, 'secret', true, algorithm: 'HS256') }.to raise_error(JWT::Base64DecodeError, 'Invalid base64 encoding')
    end
  end

  context 'when token ends with a newline char and strict_decoding enabled' do
    let(:token) { "#{JWT.encode(payload, 'secret', 'HS256')}\n" }
    before do
      JWT.configuration.strict_base64_decoding = true
    end

    it 'raises JWT::DecodeError' do
      expect { JWT.decode(token, 'secret', true, algorithm: 'HS256') }.to raise_error(JWT::DecodeError, 'Invalid base64 encoding')
    end
  end

  context 'when multiple algorithms given' do
    let(:token) { JWT.encode(payload, 'secret', 'HS256') }

    it 'starts trying with the algorithm referred in the header' do
      allow(JWT::JWA::Rsa).to receive(:verify)
      JWT.decode(token, 'secret', true, algorithm: %w[RS512 HS256])
      expect(JWT::JWA::Rsa).not_to have_received(:verify)
    end
  end

  context 'when keyfinder resolves to multiple keys and multiple algorithms given' do
    let(:iss_key_mappings) do
      {
        'ES256' => [data['ES256_public_v2'], data['ES256_public']],
        'HS256' => data['HS256']
      }
    end

    context 'with issue with ES256 keys' do
      it 'tries until the first match' do
        token = JWT.encode(payload, data['ES256_private'], 'ES256', 'iss' => 'ES256')
        result = JWT.decode(token, nil, true, algorithm: %w[ES256 HS256]) do |header, _|
          iss_key_mappings[header['iss']]
        end

        expect(result).to include(payload)
      end

      it 'tries until the first match' do
        token = JWT.encode(payload, data['ES256_private_v2'], 'ES256', 'iss' => 'ES256')
        result = JWT.decode(token, nil, true, algorithm: %w[ES256 HS256]) do |header, _|
          iss_key_mappings[header['iss']]
        end

        expect(result).to include(payload)
      end
    end

    context 'with issue with HS256 keys' do
      it 'tries until the first match' do
        token = JWT.encode(payload, data['HS256'], 'HS256', 'iss' => 'HS256')
        result = JWT.decode(token, nil, true, algorithm: %w[ES256 HS256]) do |header, _|
          iss_key_mappings[header['iss']]
        end

        expect(result).to include(payload)
      end
    end
  end

  context 'when token is missing the alg header' do
    let(:token) { 'e30.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.DIKUOt1lwwzWSPBf508IYqk0KzC2PL97OZc6pECzE1I' }

    it 'raises JWT::IncorrectAlgorithm error' do
      expect { JWT.decode(token, 'secret', true, algorithm: 'HS256') }.to raise_error(JWT::IncorrectAlgorithm, 'Token is missing alg header')
    end
  end

  context 'when token has null as the alg header' do
    let(:token) { 'eyJhbGciOm51bGx9.eyJwYXkiOiJsb2FkIn0.pizVPWJMK-GUuXXEcQD_faZGnZqz_6wKZpoGO4RdqbY' }
    it 'raises JWT::IncorrectAlgorithm error' do
      expect { JWT.decode(token, 'secret', true, algorithm: 'HS256') }.to raise_error(JWT::IncorrectAlgorithm, 'Token is missing alg header')
    end
  end

  context 'when the alg is invalid' do
    let(:token) { 'eyJhbGciOiJIUzI1NiJ9.eyJwYXkiOiJsb2FkIn0.ZpAhTTtuo-CmbgT6-95NaM_wFckKeyI157baZ29H41o' }

    it 'raises JWT::IncorrectAlgorithm error' do
      expect { JWT.decode(token, 'secret', true, algorithm: 'invalid-HS256') }.to raise_error(JWT::IncorrectAlgorithm, 'Expected a different algorithm')
    end
  end

  context 'when algorithm is a custom class' do
    let(:custom_algorithm) do
      Class.new do
        include JWT::JWA::SigningAlgorithm

        def initialize(signature: 'custom_signature', alg: 'custom')
          @signature = signature
          @alg       = alg
        end

        def sign(*)
          @signature
        end

        def verify(data:, signature:, verification_key:) # rubocop:disable Lint/UnusedMethodArgument
          signature == @signature
        end
      end
    end

    let(:token) { JWT.encode(payload, 'secret', custom_algorithm.new) }
    let(:expected_token) { 'eyJhbGciOiJjdXN0b20ifQ.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.Y3VzdG9tX3NpZ25hdHVyZQ' }

    it 'can be used for encoding' do
      expect(token).to eq(expected_token)
    end

    it 'can be used for decoding' do
      expect(JWT.decode(token, 'secret', true, algorithm: custom_algorithm.new)).to eq([payload, { 'alg' => 'custom' }])
    end

    context 'when multiple custom algorithms are given for decoding' do
      it 'tries until the first match' do
        expect(JWT.decode(token, 'secret', true, algorithms: [custom_algorithm.new(signature: 'not_this'), custom_algorithm.new])).to eq([payload, { 'alg' => 'custom' }])
      end
    end

    context 'when class has custom header method' do
      before do
        custom_algorithm.class_eval do
          def header(*)
            { 'alg' => alg, 'foo' => 'bar' }
          end
        end
      end

      it 'uses the provided header' do
        expect(JWT.decode(token, 'secret', true, algorithm: custom_algorithm.new)).to eq([payload, { 'alg' => 'custom', 'foo' => 'bar' }])
      end
    end

    context 'when class is not utilizing the ::JWT::JWA::SigningAlgorithm module' do
      let(:custom_algorithm) do
        Class.new do
          attr_reader :alg

          def initialize(signature: 'custom_signature', alg: 'custom')
            @signature = signature
            @alg       = alg
          end

          def header(*)
            { 'alg' => @alg, 'foo' => 'bar' }
          end

          def sign(*)
            @signature
          end

          def verify(*)
            true
          end
        end
      end

      it 'raises an error' do
        expect { token }.to raise_error(ArgumentError, 'Custom algorithms are required to include JWT::JWA::SigningAlgorithm')
      end
    end

    context 'when alg is not matching' do
      it 'fails the validation process' do
        expect { JWT.decode(token, 'secret', true, algorithms: custom_algorithm.new(alg: 'not_a_match')) }.to raise_error(JWT::IncorrectAlgorithm, 'Expected a different algorithm')
      end
    end

    context 'when signature is not matching' do
      it 'fails the validation process' do
        expect { JWT.decode(token, 'secret', true, algorithms: custom_algorithm.new(signature: 'not_a_match')) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when #sign method is missing' do
      before do
        custom_algorithm.instance_eval do
          remove_method :sign
        end
      end

      it 'raises an error on encoding' do
        expect { token }.to raise_error(JWT::EncodeError, /missing the sign method/)
      end

      it 'allows decoding' do
        expect(JWT.decode(expected_token, 'secret', true, algorithm: custom_algorithm.new)).to eq([payload, { 'alg' => 'custom' }])
      end
    end

    context 'when #verify method is missing' do
      before do
        custom_algorithm.instance_eval do
          remove_method :verify
        end
      end

      it 'can be used for encoding' do
        expect(token).to eq(expected_token)
      end

      it 'raises error on decoding' do
        expect { JWT.decode(expected_token, 'secret', true, algorithm: custom_algorithm.new) }.to raise_error(JWT::DecodeError, /missing the verify method/)
      end
    end
  end
end
