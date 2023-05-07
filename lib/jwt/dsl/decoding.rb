# frozen_string_literal: true

module JWT
  module DSL
    module Decoding
      def allowed_algorithms(*algorithms)
        @allowed_algorithms = algorithms.map { |algorithm| JWA.create(algorithm) } unless algorithms.empty?
        @allowed_algorithms
      end

      def decoder(value = nil)
        @decoder = value unless value.nil?
        @decoder || Decoders::Base64Json
      end

      def verification_key_finder(&finder)
        @verification_key_finder = finder if finder
        @verification_key_finder
      end

      def decoding_validator(value = nil)
        @decoding_validator = value unless value.nil?
        @decoding_validator || Validators::Noop
      end

      def decode(token:, verification_key: nil)
        DecodeContext.new(token: token,
                          decoder: decoder,
                          allowed_algorithms: allowed_algorithms,
                          verification_key: verification_key,
                          verification_key_finder: verification_key_finder)
      end
    end
  end
end
