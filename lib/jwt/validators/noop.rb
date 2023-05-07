# frozen_string_literal: true

module JWT
  module Validators
    module Noop
      def self.validate!(payload); end
    end
  end
end
