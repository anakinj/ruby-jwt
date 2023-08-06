# frozen_string_literal: true

module JWT
  module Validators
    class ClaimsValidator
      DEFAULTS = {
        leeway: 0
      }.freeze

      class << self
        %w[verify_iat verify_iss verify_jti verify_sub verify_required_claims].each do |method_name|
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
        @options = DEFAULTS.merge(options)
      end

      def verify_iat
        return unless contains_key?(@payload, 'iat')

        iat = @payload['iat']
        raise(JWT::InvalidIatError, 'Invalid iat') if !iat.is_a?(Numeric) || iat.to_f > Time.now.to_f
      end

      def verify_iss
        return unless (options_iss = @options[:iss])

        iss = @payload['iss']

        options_iss = Array(options_iss).map { |item| item.is_a?(Symbol) ? item.to_s : item }

        case iss
        when *options_iss
          nil
        else
          raise(JWT::InvalidIssuerError, "Invalid issuer. Expected #{options_iss}, received #{iss || '<none>'}")
        end
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

      def verify_sub
        return unless (options_sub = @options[:sub])

        sub = @payload['sub']
        raise(JWT::InvalidSubError, "Invalid subject. Expected #{options_sub}, received #{sub || '<none>'}") unless sub.to_s == options_sub.to_s
      end

      def verify_required_claims
        return unless (options_required_claims = @options[:required_claims])

        options_required_claims.each do |required_claim|
          raise(JWT::MissingRequiredClaim, "Missing required claim #{required_claim}") unless @payload.include?(required_claim)
        end
      end

      private

      def global_leeway
        @options[:leeway]
      end

      def exp_leeway
        @options[:exp_leeway] || global_leeway
      end

      def contains_key?(payload, key)
        payload.respond_to?(:key?) && payload.key?(key)
      end
    end
  end
end
