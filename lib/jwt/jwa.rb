# frozen_string_literal: true

require 'openssl'
require 'jwt/jwa/hmac'
require 'jwt/jwa/eddsa'
require 'jwt/jwa/ecdsa'
require 'jwt/jwa/rsa'
require 'jwt/jwa/ps'
require 'jwt/jwa/none'
require 'jwt/jwa/unsupported'
require 'jwt/jwa/algo_wrapper'

module JWT
  module JWA
    extend self

    ALGOS = [Hmac, Ecdsa, Rsa, Eddsa, Ps, None, Unsupported].freeze

    def find(algorithm)
      indexed[algorithm && algorithm.downcase]
    end

    def create(algorithm)
      AlgoWrapper.new(*find(algorithm))
    end

    def implementation?(algorithm)
      (algorithm.respond_to?(:valid_alg?) && algorithm.respond_to?(:verify)) ||
        (algorithm.respond_to?(:alg) && algorithm.respond_to?(:sign))
    end

    private

    def indexed
      @indexed ||= begin
        fallback = [nil, Unsupported]
        ALGOS.each_with_object(Hash.new(fallback)) do |cls, hash|
          cls.const_get(:SUPPORTED).each do |alg|
            hash[alg.downcase] = [alg, cls]
          end
        end
      end
    end
  end
end