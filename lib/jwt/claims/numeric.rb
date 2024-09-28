# frozen_string_literal: true

module JWT
  module Claims
    class Numeric # :nodoc:
      NUMERIC_CLAIMS = %i[
        exp
        iat
        nbf
      ].freeze

      def verify!(context:)
        validate_numeric_claims(context.payload)
      end

      private

      def validate_numeric_claims(payload)
        NUMERIC_CLAIMS.each do |claim|
          validate_is_numeric(payload, claim)
        end
      end

      def validate_is_numeric(payload, claim)
        return unless payload.is_a?(Hash)
        return unless payload.key?(claim) ||
                      payload.key?(claim.to_s)

        return if payload[claim].is_a?(::Numeric) || payload[claim.to_s].is_a?(::Numeric)

        raise InvalidPayload, "#{claim} claim must be a Numeric value but it is a #{(payload[claim] || payload[claim.to_s]).class}"
      end
    end
  end
end
