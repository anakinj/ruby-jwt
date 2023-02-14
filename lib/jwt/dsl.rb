# frozen_string_literal: true

require_relative 'dsl/encode'
require_relative 'dsl/decode'

module JWT
  module DSL
    def self.included(cls)
      cls.include(Encode)
      cls.include(Decode)
    end
  end
end
