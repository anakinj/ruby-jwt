# frozen_string_literal: true

require_relative 'claims/audience'
require_relative 'claims/expiration'
require_relative 'claims/issued_at'
require_relative 'claims/issuer'
require_relative 'claims/jwt_id'
require_relative 'claims/not_before'
require_relative 'claims/numeric'
require_relative 'claims/required'
require_relative 'claims/subject'
require_relative 'claims/decode'

module JWT
  module Claims # :nodoc:
    Error = Struct.new(:message, keyword_init: true)

    VERIFIERS = {
      exp: ->(options) { Claims::Expiration.new(leeway: options.dig(:exp, :leeway)) },
      nbf: ->(options) { Claims::NotBefore.new(leeway: options.dig(:nbf, :leeway)) },
      iss: ->(options) { Claims::Issuer.new(issuers: options[:iss]) },
      iat: ->(*) { Claims::IssuedAt.new },
      jti: ->(options) { Claims::JwtId.new(validator: options[:jti]) },
      aud: ->(options) { Claims::Audience.new(expected_audience: options[:aud]) },
      sub: ->(options) { Claims::Subject.new(expected_subject: options[:sub]) },
      required_claims: ->(options) { Claims::Required.new(required_claims: options[:required_claims]) },
      numeric: ->(*) { Claims::Numeric.new }
    }.freeze

    class << self
      def verify!(token, *options)
        iterate_verifiers(*options) do |verifier, verifier_options|
          verify_one!(token, verifier, verifier_options)
        end
        nil
      end

      def errors(token, *options)
        errors = []
        iterate_verifiers(*options) do |verifier, verifier_options|
          verify_one!(token, verifier, verifier_options)
        rescue ::JWT::DecodeError => e
          errors << Error.new(message: e.message)
        end
        errors
      end

      def iterate_verifiers(*options)
        options.each do |element|
          if element.is_a?(Hash)
            element.each_key { |key| yield(key, element) }
          else
            yield(element, {})
          end
        end
      end

      private

      def verify_one!(token, verifier, options)
        verifier_builder = VERIFIERS.fetch(verifier) { raise ArgumentError, "#{verifier} not a valid claim verifier" }
        verifier_builder.call(options || {}).verify!(context: token)
      end
    end
  end
end
