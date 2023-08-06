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

require_relative 'jwt/validators/audience_claim_validator'
require_relative 'jwt/validators/claims_validator'
require_relative 'jwt/validators/expiration_claim_validator'
require_relative 'jwt/validators/not_before_claim_validator'
require_relative 'jwt/validators/numeric_claims_validator'
require_relative 'jwt/validators/subject_claim_validator'
require_relative 'jwt/validators/token_segement_validator'

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
    encode_validators << Validators::NumericClaimsValidator
  end

  def encode(payload, key, signing_algorithm = nil, headers = nil)
    DefaultEncoder.sign_and_encode(payload: payload, headers: headers, signing_key: key, signing_algorithm: signing_algorithm)
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
    DefaultDecoder.new(token: jwt,
                       verification_key: key,
                       verify: verify,
                       keyfinder: keyfinder,
                       allowed_algorithms: normalizde_algorithm_option(options),
                       **configuration.decode.to_h.merge(options).transform_keys(&:to_sym)).decode_segments
  end

  # Order is very important - first check for string keys, next for symbols
  ALGORITHM_KEYS = ['algorithm',
                    :algorithm,
                    'algorithms',
                    :algorithms].freeze
  def normalizde_algorithm_option(options)
    ALGORITHM_KEYS.map { |alg_key| options.delete(alg_key) }.compact.first ||
      configuration.decode.algorithms
  end
end
