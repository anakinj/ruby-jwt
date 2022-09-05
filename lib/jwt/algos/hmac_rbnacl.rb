# frozen_string_literal: true

module JWT
  module Algos
    module HmacRbNaCl
      module_function

      MAPPING = {
        'HS256' => RbNaCl::HMAC::SHA256,
        'HS512256' => RbNaCl::HMAC::SHA512256,
        'HS384' => nil,
        'HS512' => RbNaCl::HMAC::SHA512
      }.freeze

      SUPPORTED = MAPPING.keys

      def sign(to_sign)
        algorithm, msg, key = to_sign.values
        key ||= ''
        if (hmac = MAPPING.fetch(algorithm)) && key.bytesize <= hmac.key_bytes
          hmac.auth(padded_key_bytes(key, hmac.key_bytes), msg.encode('binary'))
        else
          Hmac.sign(to_sign)
        end
      end

      def verify(to_verify)
        algorithm, key, signing_input, signature = to_verify.values

        if (hmac = MAPPING.fetch(algorithm)) && key.bytesize <= hmac.key_bytes
          hmac.verify(padded_key_bytes(key, hmac.key_bytes), signature.encode('binary'), signing_input.encode('binary'))
        else
          Hmac.verify(to_verify)
        end
      rescue RbNaCl::BadAuthenticatorError
        false
      end

      def padded_key_bytes(key, bytesize)
        key.bytes.fill(0, key.bytesize...bytesize).pack('C*')
      end
    end
  end
end
