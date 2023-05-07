# frozen_string_literal: true

require_relative 'dsl/encoding'
require_relative 'dsl/decoding'

module JWT
  module DSL
    def self.included(cls)
      cls.include(Encoding)
      cls.include(Decoding)
    end
  end
end
