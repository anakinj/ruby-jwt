# frozen_string_literal: true

require_relative 'x5c_key_finder'

module JWT
  class DefaultDecoder
    def self.define_decoder(options)
      JWT.define do
        allowed_algorithms(*options[:allowed_algorithms])

        if options[:verification_key]
          verification_key(options[:verification_key])
        end

        if options[:keyfinder]
          verification_key(options[:keyfinder])
        end

        if options[:jwks]
          verification_key do |header, _payload|
            ::JWT::JWK::KeyFinder.new(jwks: options[:jwks],
                                      allow_nil_kid: options[:allow_nil_kid]).key_for(header['kid'])
          end
        end

        if (x5c_options = options[:x5c])
          verification_key do |header, _payload|
            X5cKeyFinder.new(x5c_options[:root_certificates], x5c_options[:crls]).from(header['x5c'])
          end
        end
      end
    end

    def initialize(token:, verify:, **options)
      raise(JWT::DecodeError, 'Nil JSON web token') unless token

      @options = options
      @verify  = verify

      decoder         = self.class.define_decoder(options)
      @decode_context = decoder.decode(token: token)
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

    def allowed_algorithms
      @allowed_algorithms ||= resolve_allowed_algorithms
    end

    def resolve_allowed_algorithms
      Array(@options[:allowed_algorithms]).map do |alg|
        if JWA.implementation?(alg)
          alg
        else
          JWA.create(alg)
        end
      end
    end

    def verify_claims
      Validators::ClaimsValidator.verify_claims(payload, @options)
      Validators::ClaimsValidator.verify_required_claims(payload, @options)
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
