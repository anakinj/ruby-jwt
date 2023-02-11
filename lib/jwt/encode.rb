# frozen_string_literal: true

require_relative 'jwa'
require_relative 'claims_validator'

module JWT
  class Encode
    ALG_KEY = 'alg'

    def initialize(options)
      @payload          = options[:payload]
      @key              = options[:key]
      @algorithm        = resolve_algorithm(options[:algorithm])
      @headers          = options[:headers].transform_keys(&:to_s)
      @headers[ALG_KEY] = @algorithm.alg
    end

    def segments
      validate_claims!
      combine(encoded_header_and_payload, encoded_signature)
    end

    private

    def resolve_algorithm(algorithm)
      return algorithm if JWA.implementation?(algorithm)

      JWA.create(algorithm)
    end

    def encoded_header
      @encoded_header ||= encode_header
    end

    def encoded_payload
      @encoded_payload ||= encode_payload
    end

    def encoded_signature
      @encoded_signature ||= encode_signature
    end

    def encoded_header_and_payload
      @encoded_header_and_payload ||= combine(encoded_header, encoded_payload)
    end

    def encode_header
      encode_data(@headers)
    end

    def encode_payload
      encode_data(@payload)
    end

    def signature
      @algorithm.sign(data: encoded_header_and_payload, signing_key: @key)
    end

    def validate_claims!
      return unless @payload.is_a?(Hash)

      ClaimsValidator.new(@payload).validate!
    end

    def encode_signature
      Base64.urlsafe_encode64(signature, padding: false)
    end

    def encode_data(data)
      Base64.urlsafe_encode64(::JSON.generate(data), padding: false)
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
