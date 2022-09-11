# frozen_string_literal: true

require 'jwt/algos/hmac'
require 'jwt/algos/eddsa'
require 'jwt/algos/ecdsa'
require 'jwt/algos/rsa'
require 'jwt/algos/ps'
require 'jwt/algos/none'
require 'jwt/algos/unsupported'

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

# JWT::Signature module
module JWT
  # Signature logic for JWT
  module Algos
    extend self

    ALGOS = begin
      list = [
        Algos::Ecdsa,
        Algos::Rsa,
        Algos::Eddsa,
        Algos::Ps,
        Algos::None,
        Algos::Unsupported
      ]

      list << if ::JWT.rbnacl_6_or_greater?
        require_relative 'algos/hmac_rbnacl'
        Algos::HmacRbNaCl
      elsif ::JWT.rbnacl?
        require_relative 'algos/hmac_rbnacl_fixed'
        Algos::HmacRbNaClFixed
      else
        Algos::Hmac
      end
    end.freeze

    def find(algorithm)
      indexed[algorithm && algorithm.downcase]
    end

    private

    def indexed
      @indexed ||= begin
        fallback = [Algos::Unsupported, nil]
        ALGOS.each_with_object(Hash.new(fallback)) do |alg, hash|
          alg.const_get(:SUPPORTED).each do |code|
            hash[code.downcase] = [alg, code]
          end
        end
      end
    end
  end
end
