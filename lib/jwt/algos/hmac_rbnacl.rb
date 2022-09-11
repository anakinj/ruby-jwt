# frozen_string_literal: true

module JWT
  module Algos
    module HmacRbNaCl
      module_function

      MAPPING = {
        'HS256' => ::RbNaCl::HMAC::SHA256,
        'HS512256' => ::RbNaCl::HMAC::SHA512256,
        'HS384' => nil,
        'HS512' => ::RbNaCl::HMAC::SHA512
      }.freeze

      SUPPORTED = MAPPING.keys

      def sign(to_sign)
        algorithm, msg, key = to_sign.values
        if (hmac = resolve_algorithm(algorithm))
          key ||= ''
          hmac.auth(key.encode('binary'), msg.encode('binary'))
        else
          Hmac.sign(to_sign)
        end
      end

      def verify(to_verify)
        algorithm, key, signing_input, signature = to_verify.values

        if (hmac = resolve_algorithm(algorithm))
          hmac.verify(key.encode('binary'), signature.encode('binary'), signing_input.encode('binary'))
        else
          Hmac.verify(to_verify)
        end
      rescue ::RbNaCl::BadAuthenticatorError
        false
      end

      def resolve_algorithm(algorithm)
        MAPPING.fetch(algorithm)
      end
    end
  end
end
