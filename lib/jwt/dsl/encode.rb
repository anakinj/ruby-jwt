# frozen_string_literal: true

require 'json'
require 'base64'

module JWT
  module JsonAndBase64Encoder
    def self.encode(type:, value:)
      value = ::JSON.generate(value) if type != :signature
      ::Base64.urlsafe_encode64(value, padding: false)
    end
  end

  module PayloadClaimsValidator
    def self.validate!(payload)
      return unless payload.is_a?(Hash)

      ClaimsValidator.new(payload).validate!
    end
  end

  module DSL
    module NoopValidator
      def self.validate!(payload); end
    end

    module Encode
      def signing_algorithm(value = nil)
        @signing_algorithm = JWA.create(value) unless value.nil?
        @signing_algorithm
      end

      def encoder(value = nil)
        @encoder = value unless value.nil?
        @encoder || JsonAndBase64Encoder
      end

      def validator(value = nil)
        @validator = value unless value.nil?
        @validator || NoopValidator
      end

      def sign_and_encode(payload:, headers: nil, signing_algorithm: nil, signing_key: nil)
        validator.validate!(payload)
        algorithm = if signing_algorithm
          JWA.create(signing_algorithm)
        else
          self.signing_algorithm
        end
        complete_headers = { 'alg' => algorithm.alg }
        complete_headers.merge!(headers.transform_keys(&:to_s)) if headers
        header_and_payload = combine(encode(type: :header, value: complete_headers),
                                     encode(type: :payload, value: payload))
        encoded_signature = encode(type: :signature, value: algorithm.sign(data: header_and_payload, signing_key: signing_key))
        combine(header_and_payload, encoded_signature)
      end

      private

      def encode(type:, value:)
        encoder.encode(type: type, value: value)
      end

      def combine(*parts)
        parts.join('.')
      end
    end
  end
end
