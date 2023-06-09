# frozen_string_literal: true

module JWT
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
      @verification_keys ||= Array(resolve_verification_keys).compact
    end

    def algorithm_match?
      !allowed_and_valid_algorithms.empty?
    end

    private

    def resolve_verification_keys
      return verification_key.call(header, payload) if verification_key.respond_to?(:call)

      verification_key
    end

    def valid_signature_for?(key)
      allowed_and_valid_algorithms.any? do |alg|
        alg.verify(data: token.raw_header_and_payload, signature: token.signature, verification_key: key)
      end
    end

    def allowed_and_valid_algorithms
      @allowed_and_valid_algorithms ||= allowed_algorithms.select { |alg| alg.valid_alg?(token.alg_in_header) }
    end
  end
end
