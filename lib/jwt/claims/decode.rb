# frozen_string_literal: true

module JWT
  module Claims
    module Decode # :nodoc:
      VERIFIERS = {
        verify_expiration: ->(options) { Claims::Expiration.new(leeway: options[:exp_leeway] || options[:leeway]) },
        verify_not_before: ->(options) { Claims::NotBefore.new(leeway: options[:nbf_leeway] || options[:leeway]) },
        verify_iss: ->(options) { options[:iss] && Claims::Issuer.new(issuers: options[:iss]) },
        verify_iat: ->(*) { Claims::IssuedAt.new },
        verify_jti: ->(options) { Claims::JwtId.new(validator: options[:verify_jti]) },
        verify_aud: ->(options) { options[:aud] && Claims::Audience.new(expected_audience: options[:aud]) },
        verify_sub: ->(options) { options[:sub] && Claims::Subject.new(expected_subject: options[:sub]) },
        required_claims: ->(options) { Claims::Required.new(required_claims: options[:required_claims]) }
      }.freeze

      class << self
        def verify!(token, options)
          VERIFIERS.each do |key, verifier_builder|
            next unless options[key]

            verifier_builder&.call(options)&.verify!(context: token)
          end
        end
      end
    end
  end
end
