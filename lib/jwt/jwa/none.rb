# frozen_string_literal: true

module JWT
  module JWA
    module None
      SUPPORTED = %w[none].freeze

      class << self
        def sign(*)
          ''
        end

        def verify(*)
          true
        end
      end

      ::JWT::JWA.register(SUPPORTED, self)
    end
  end
end
