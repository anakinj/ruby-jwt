# frozen_string_literal: true

module JWT
  module Algos
    module HmacRbNaCl
      class << self
        def sign(algorithm, msg, key)
          Deprecations.warning("The use of the algorithm #{algorithm} is deprecated and will be removed in the next major version of ruby-jwt")

          ::RbNaCl::HMAC::SHA512256.auth(key_for_rbnacl(::RbNaCl::HMAC::SHA512256, key).encode('binary'), msg.encode('binary'))
        end

        def verify(algorithm, key, signing_input, signature)
          Deprecations.warning("The use of the algorithm #{algorithm} is deprecated and will be removed in the next major version of ruby-jwt")

          ::RbNaCl::HMAC::SHA512256.verify(key_for_rbnacl(::RbNaCl::HMAC::SHA512256, key).encode('binary'), signature.encode('binary'), signing_input.encode('binary'))
        rescue ::RbNaCl::BadAuthenticatorError, ::RbNaCl::LengthError
          false
        end

        private

        def key_for_rbnacl(hmac, key)
          key ||= ''
          raise JWT::DecodeError, 'HMAC key expected to be a String' unless key.is_a?(String)

          return padded_empty_key(hmac.key_bytes) if key == ''

          key
        end

        def padded_empty_key(length)
          Array.new(length, 0x0).pack('C*').encode('binary')
        end
      end

      ::JWT::JWA.register('HS512256', self)
    end
  end
end
