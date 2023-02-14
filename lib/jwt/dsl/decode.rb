# frozen_string_literal: true

require 'json'
require 'base64'

module JWT
  module JsonAndBase64Decoder
    def self.decode(type:, value:)
      value = ::Base64.urlsafe_decode64(value)
      value = ::JSON.parse(value) if type != :signature
      value
    rescue ::JSON::ParserError, ArgumentError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end

  class Token
    attr_reader :value, :decoder

    def initialize(value:, decoder:)
      @value = value
      @decoder = decoder
    end

    def segments
      @segments ||= value.split('.')
    end

    def segment_count
      segments.size
    end

    def raw_payload
      segments[1]
    end

    def raw_signature
      segments[2]
    end

    def raw_header_and_payload
      segments.first(2).join('.')
    end

    def raw_header
      segments.first
    end

    def header
      decoder.decode(type: :header, value: raw_header)
    end

    def signature
      decoder.decode(type: :signature, value: raw_signature) if raw_signature
    end

    def payload
      decoder.decode(type: :payload, value: raw_payload)
    end

    def alg_in_header
      header['alg']
    end
  end

  class DecodeContext
    attr_reader :token, :allowed_algorithms, :verification_key

    def initialize(token:, decoder:, allowed_algorithms:, verification_key:)
      @token = Token.new(value: token, decoder: decoder)
      @allowed_algorithms = allowed_algorithms
      @verification_key = verification_key
    end

    def header
      token.header
    end

    def payload
      token.payload
    end

    def valid_signature?
      verification_keys.any? { |key| valid_signature_for?(key) }
    end

    def verification_keys
      Array(verification_key).compact
    end

    def algorithm_match?
      !allowed_and_valid_algorithms.empty?
    end

    private

    def valid_signature_for?(key)
      allowed_and_valid_algorithms.any? do |alg|
        alg.verify(data: token.raw_header_and_payload, signature: token.signature, verification_key: key)
      end
    end

    def allowed_and_valid_algorithms
      @allowed_and_valid_algorithms ||= allowed_algorithms.select { |alg| alg.valid_alg?(token.alg_in_header) }
    end
  end

  module DSL
    module Decode
      def allowed_algorithms(*algorithms)
        @allowed_algorithms = algorithms.map { |algorithm| JWA.create(algorithm) } unless algorithms.empty?
        @allowed_algorithms
      end

      def decoder(value = nil)
        @decoder = value unless value.nil?
        @decoder || JsonAndBase64Decoder
      end

      def decode(token:, verification_key: nil)
        DecodeContext.new(token: token,
                          decoder: decoder,
                          allowed_algorithms: allowed_algorithms,
                          verification_key: verification_key)
      end
    end
  end
end
