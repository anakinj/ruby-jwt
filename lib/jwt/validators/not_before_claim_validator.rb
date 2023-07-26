# frozen_string_literal: true

module JWT
  module Validators
    class NotBeforeClaimValidator
      def initialize(leeway:)
        @leeway = leeway
      end

      def validate!(context:, **_args)
        return unless context.payload.is_a?(Hash)
        return unless context.payload.key?('nbf')

        raise JWT::ImmatureSignature, 'Signature nbf has not been reached' if context.payload['nbf'].to_i > (Time.now.to_i + leeway)
      end

      def type?(type)
        type == :claims
      end

      private

      attr_reader :leeway
    end
  end
end
