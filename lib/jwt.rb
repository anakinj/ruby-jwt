# frozen_string_literal: true

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

require 'jwt/version'
require 'jwt/decode'
require 'jwt/configuration'
require 'jwt/encode'
require 'jwt/error'
require 'jwt/jwk'

module JWT
  extend ::JWT::Configuration

  module_function

  def encode(payload, key, algorithm = 'HS256', header_fields = {})
    Encode.new(payload: payload,
               key: key,
               algorithm: algorithm,
               headers: header_fields).segments
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
    Decode.new(jwt, key, verify, configuration.decode.to_h.merge(options), &keyfinder).decode_segments
  end
end
