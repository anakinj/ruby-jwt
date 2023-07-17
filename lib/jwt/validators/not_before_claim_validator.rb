# frozen_string_literal: true

module JWT
  module Validators
    class NotBeforeClaimValidator
      def initialize(leeway:)
        @leeway = leeway
      end

      def validate!(payload:, **_args)
        return unless payload.is_a?(Hash)
        return unless payload.key?('nbf')

        raise JWT::ImmatureSignature, 'Signature nbf has not been reached' if payload['nbf'].to_i > (Time.now.to_i + leeway)
      end

      private

      attr_reader :leeway
    end
  end
end
