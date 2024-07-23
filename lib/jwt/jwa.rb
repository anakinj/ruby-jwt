# frozen_string_literal: true

require 'openssl'

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

require_relative 'jwa/unsupported'
require_relative 'jwa/wrapper'

module JWT
  module JWA
    class << self
      def find(algorithm)
        registered[algorithm&.downcase]
      end

      def create(algorithm)
        return algorithm if JWA.implementation?(algorithm)

        find(algorithm)
      end

      def register(algorithms, implementation)
        Array(algorithms).each do |algo|
          registered[algo.downcase] = implementation?(implementation) ? implementation : Wrapper.new(algo, implementation)
        end
      end

      def implementation?(algorithm)
        (algorithm.respond_to?(:valid_alg?) && algorithm.respond_to?(:verify)) ||
          (algorithm.respond_to?(:alg) && algorithm.respond_to?(:sign))
      end

      private

      def registered
        @registered ||= Hash.new(Unsupported)
      end
    end
  end
end

require_relative 'jwa/hmac'
require_relative 'jwa/eddsa'
require_relative 'jwa/ecdsa'
require_relative 'jwa/rsa'
require_relative 'jwa/ps'
require_relative 'jwa/none'

if JWT.rbnacl_6_or_greater?
  require_relative 'jwa/hmac_rbnacl'
elsif JWT.rbnacl?
  require_relative 'jwa/hmac_rbnacl_fixed'
end
