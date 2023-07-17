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

      def verification_key(value = nil, &block)
        @verification_key = value if value
        @verification_key = block if block
        @verification_key
      end

      def decoding_validator(value = nil)
        @decoding_validator = value unless value.nil?
        @decoding_validator || Validators::Noop
      end

      def validators
        @validators ||= []
      end

      def decode(token:, **options)
        DecodeContext.new(**{ token: token,
                              decoder: decoder,
                              allowed_algorithms: allowed_algorithms,
                              verification_key: verification_key,
                              validators: validators }.merge(options))
      end
    end
  end
end
