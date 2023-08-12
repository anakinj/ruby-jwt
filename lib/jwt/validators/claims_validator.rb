# frozen_string_literal: true

module JWT
  module Validators
    class ClaimsValidator
      class << self
        %w[verify_jti].each do |method_name|
          define_method method_name do |payload, options|
            new(payload, options).send(method_name)
          end
        end

        def verify_claims(payload, options)
          options.each do |key, val|
            next unless key.to_s =~ /verify/ && respond_to?(key)

            send(key, payload, options) if val
          end
        end
      end

      def initialize(payload, options)
        @payload = payload
        @options = options
      end

      def verify_jti
        options_verify_jti = @options[:verify_jti]
        jti = @payload['jti']

        if options_verify_jti.respond_to?(:call)
          verified = options_verify_jti.arity == 2 ? options_verify_jti.call(jti, @payload) : options_verify_jti.call(jti)
          raise(JWT::InvalidJtiError, 'Invalid jti') unless verified
        elsif jti.to_s.strip.empty?
          raise(JWT::InvalidJtiError, 'Missing jti')
        end
      end
    end
  end
end
