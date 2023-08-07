# frozen_string_literal: true

module JWT
  module Validators
    class IssuedAtClaimValidator
      def validate!(context:, **_args)
        return unless context.payload.is_a?(Hash)
        return unless context.payload.key?('iat')

        iat = context.payload['iat']
        raise(JWT::InvalidIatError, 'Invalid iat') if !iat.is_a?(Numeric) || iat.to_f > Time.now.to_f
      end

      def type?(type)
        type == :claims
      end
    end
  end
end
