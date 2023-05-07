# frozen_string_literal: true

module JWT
  module Decoders
    module Base64Json
      def self.decode(type:, value:)
        value = ::Base64.urlsafe_decode64(value)
        value = ::JSON.parse(value) if type != :signature
        value
      rescue ::JSON::ParserError, ArgumentError
        raise JWT::DecodeError, 'Invalid segment encoding'
      end

      def self.encode(type:, value:)
        value = ::JSON.generate(value) if type != :signature
        ::Base64.urlsafe_encode64(value, padding: false)
      end
    end
  end
end
