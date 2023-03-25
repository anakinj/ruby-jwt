# frozen_string_literal: true

require_relative 'verify'
require_relative 'x5c_key_finder'
require_relative 'claims_validator'

module JWT
  class DefaultDecoder
    def self.define_decoder(options, keyfinder)
      JWT.define do
        allowed_algorithms(*Array(options['algorithm'] || options[:algorithm] || options['algorithms'] || options[:algorithms]))

        if keyfinder
          verification_key_finder(&keyfinder)
        end

        if options[:jwks]
          verification_key_finder do |header, _payload|
            ::JWT::JWK::KeyFinder.new(jwks: options[:jwks],
                                      allow_nil_kid: options[:allow_nil_kid]).key_for(header['kid'])
          end
        end

        if (x5c_options = options[:x5c])
          verification_key_finder do |header, _payload|
            X5cKeyFinder.new(x5c_options[:root_certificates], x5c_options[:crls]).from(header['x5c'])
          end
        end
      end
    end

    def initialize(jwt, key, verify, options, &keyfinder)
      raise(JWT::DecodeError, 'Nil JSON web token') unless jwt

      @options = options
      @verify = verify

      decoder = self.class.define_decoder(options, keyfinder)

      @decode_context = decoder.decode(token: jwt, verification_key: key)
    end

    attr_reader :decode_context

    def decode_segments
      validate_segment_count!

      if @verify
        verify_algo
        verify_signature
        verify_claims
      end

      [payload, header]
    end

    private

    def verify_signature
      return if none_algorithm?
      raise JWT::DecodeError, 'No verification key available' if decode_context.verification_keys.empty?

      return if decode_context.valid_signature?

      raise JWT::VerificationError, 'Signature verification failed'
    end

    def verify_algo
      raise(JWT::IncorrectAlgorithm, 'An algorithm must be specified') if allowed_algorithms.empty?
      raise(JWT::IncorrectAlgorithm, 'Token is missing alg header') unless alg_in_header
      raise(JWT::IncorrectAlgorithm, 'Expected a different algorithm') if allowed_and_valid_algorithms.empty?
    end

    def allowed_and_valid_algorithms
      @allowed_and_valid_algorithms ||= allowed_algorithms.select { |alg| alg.valid_alg?(alg_in_header) }
    end

    # Order is very important - first check for string keys, next for symbols
    ALGORITHM_KEYS = ['algorithm',
                      :algorithm,
                      'algorithms',
                      :algorithms].freeze

    def given_algorithms
      ALGORITHM_KEYS.each do |alg_key|
        alg = @options[alg_key]
        return Array(alg) if alg
      end
      []
    end

    def allowed_algorithms
      @allowed_algorithms ||= resolve_allowed_algorithms
    end

    def resolve_allowed_algorithms
      given_algorithms.map do |alg|
        if JWA.implementation?(alg)
          alg
        else
          JWA.create(alg)
        end
      end
    end

    def verify_claims
      Verify.verify_claims(payload, @options)
      Verify.verify_required_claims(payload, @options)
    end

    def validate_segment_count!
      return if decode_context.token.segment_count == 3
      return if !@verify && decode_context.token.segment_count == 2 # If no verifying required, the signature is not required
      return if decode_context.token.segment_count == 2 && none_algorithm?

      raise(JWT::DecodeError, 'Not enough or too many segments')
    end

    def none_algorithm?
      decode_context.token.alg_in_header == 'none'
    end

    def alg_in_header
      decode_context.token.alg_in_header
    end

    def header
      decode_context.token.header
    end

    def payload
      decode_context.token.payload
    end
  end
end
