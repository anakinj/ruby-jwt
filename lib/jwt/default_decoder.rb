# frozen_string_literal: true

require_relative 'x5c_key_finder'

module JWT
  # This class contains the old logic for decoding JWT tokens. Preserving backwards compatibility as best as possible.
  class DefaultDecoder
    def self.define_decoder(verify:, **options) # rubocop:disable Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      JWT.define do # rubocop:disable Metrics/BlockLength
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

        if verify
          decode_validators << Validators::TokenSegmentValidator.new(min_segment_count: 3)

          if options[:verify_expiration]
            decode_validators << Validators::ExpirationClaimValidator.new(leeway: options[:exp_leeway] || options[:leeway])
          end

          if options[:verify_not_before]
            decode_validators << Validators::NotBeforeClaimValidator.new(leeway: options[:nbf_leeway] || options[:leeway])
          end

          if options[:verify_aud] && options[:aud]
            decode_validators << Validators::AudienceClaimValidator.new(expected_audience: options[:aud])
          end
        else
          # If no verifying required, the signature is not required
          decode_validators << Validators::TokenSegmentValidator.new(min_segment_count: 2)
        end
      end
    end

    def initialize(token:, verify:, **options)
      raise(JWT::DecodeError, 'Nil JSON web token') unless token

      @options = options
      @verify  = verify

      decoder         = self.class.define_decoder(verify: verify, **options)
      @decode_context = decoder.decode(token: token)
    end

    attr_reader :decode_context

    def decode_segments
      decode_context.validate!(:raw_token)
      if @verify
        verify_algo
        decode_context.validate_signature!
        decode_context.validate!(:claims)
        verify_claims
      end

      [payload, header]
    end

    private

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
