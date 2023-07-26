# frozen_string_literal: true

module JWT
  module Validators
    class TokenSegmentValidator
      def initialize(min_segment_count: 3)
        @min_segment_count = min_segment_count
      end

      def validate!(context:, **_args)
        return if context.token.segment_count == 3 || context.token.segment_count == min_segment_count
        return if context.token.segment_count == 2 && context.token.alg_in_header == 'none'

        raise JWT::DecodeError, 'Not enough or too many segments'
      end

      def type?(type)
        type == :raw_token
      end

      private

      attr_reader :min_segment_count
    end
  end
end
