# frozen_string_literal: true

module JWT
  class DecodeContext
    attr_reader :token, :allowed_algorithms, :verification_key, :verification_key_finder

    def initialize(token:, decoder:, allowed_algorithms:, verification_key:, verification_key_finder:)
      @token = Token.new(value: token, decoder: decoder)
      @allowed_algorithms = allowed_algorithms
      @verification_key = verification_key
      @verification_key_finder = verification_key_finder
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
      @verification_keys ||= Array(verification_key_finder&.call(header, payload) || verification_key).compact
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
end
