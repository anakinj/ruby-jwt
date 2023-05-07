# frozen_string_literal: true

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

require 'base64'
require 'openssl'
require 'json'

require_relative 'jwt/version'
require_relative 'jwt/configuration'
require_relative 'jwt/error'
require_relative 'jwt/jwk'
require_relative 'jwt/jwa'
require_relative 'jwt/default_decoder'
require_relative 'jwt/dsl'

require_relative 'jwt/validators/noop'
require_relative 'jwt/validators/claims_validator'

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
    validator Validators::ClaimsValidator
  end

  def encode(payload, key, signing_algorithm = nil, headers = nil)
    DefaultEncoder.sign_and_encode(payload: payload, headers: headers, signing_key: key, signing_algorithm: signing_algorithm)
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
    DefaultDecoder.new(jwt, key, verify, configuration.decode.to_h.merge(options), &keyfinder).decode_segments
  end
end
