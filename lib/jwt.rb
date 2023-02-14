# frozen_string_literal: true

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

require 'jwt/version'
require 'jwt/decode'
require 'jwt/configuration'
require 'jwt/error'
require 'jwt/jwk'
require 'jwt/jwa'
require 'jwt/claims_validator'
require 'jwt/dsl'

module JWT
  extend ::JWT::Configuration

  module_function

  def define(&block)
    cls = Class.new do
      include ::JWT::DSL
    end.new
    cls.instance_exec(&block)
    cls
  end

  DefaultEncoder = define do
    signing_algorithm 'HS256'
    validator PayloadClaimsValidator
  end

  def encode(payload, key, signing_algorithm = nil, headers = nil)
    DefaultEncoder.sign_and_encode(payload: payload, signing_key: key, signing_algorithm: signing_algorithm, headers: headers)
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
    Decode.new(jwt, key, verify, configuration.decode.to_h.merge(options), &keyfinder).decode_segments
  end
end
