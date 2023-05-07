# frozen_string_literal: true

module JWT
  module DSL
    module Encoding
      def signing_algorithm(value = nil)
        @signing_algorithm = JWA.create(value) unless value.nil?
        @signing_algorithm
      end

      def encoder(value = nil)
        @encoder = value unless value.nil?
        @encoder || Decoders::Base64Json
      end

      def encoding_validator(value = nil)
        @encoding_validator = value unless value.nil?
        @encoding_validator || Validators::Noop
      end

      def sign_and_encode(payload:, headers: nil, signing_algorithm: nil, signing_key: nil)
        encoding_validator.validate!(payload: payload, headers: headers)

        algorithm = signing_algorithm ? JWA.create(signing_algorithm) : self.signing_algorithm

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
