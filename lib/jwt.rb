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
require_relative 'jwt/token'
require_relative 'jwt/decode_context'
require_relative 'jwt/dsl'

require_relative 'jwt/validators/noop'
require_relative 'jwt/validators/claims_validator'
require_relative 'jwt/validators/numeric_claims_validator'
require_relative 'jwt/decoders/base64_json'

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
    encoding_validator Validators::NumericClaimsValidator
  end

  def encode(payload, key, signing_algorithm = nil, headers = nil)
    DefaultEncoder.sign_and_encode(payload: payload, headers: headers, signing_key: key, signing_algorithm: signing_algorithm)
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
    DefaultDecoder.new(token: jwt,
                       verification_key: key,
                       verify: verify,
                       keyfinder: keyfinder,
                       **configuration.decode.to_h.merge(options)).decode_segments
  end
end
