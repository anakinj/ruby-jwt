# frozen_string_literal: true

module JWT
  # Represents a JWT token
  #
  # Basic token signed using the HS256 algorithm:
  #
  #   token = JWT::Token.new(payload: {pay: 'load'})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #   token.jwt # => eyJhb....
  #
  # Custom headers will be combined with generated headers:
  #   token = JWT::Token.new(payload: {pay: 'load'}, header: {custom: "value"})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #   token.header # => {"custom"=>"value", "alg"=>"HS256"}
  #
  class Token
    # Initializes a new Token instance.
    #
    # @param header [Hash] the header of the JWT token.
    # @param payload [Hash] the payload of the JWT token.
    def initialize(payload:, header: {})
      @header  = header&.transform_keys(&:to_s)
      @payload = payload
    end

    # Returns the decoded signature of the JWT token.
    #
    # @return [String] the decoded signature of the JWT token.
    def signature
      @signature ||= ::JWT::Base64.url_decode(encoded_signature || '')
    end

    # Returns the encoded signature of the JWT token.
    #
    # @return [String] the encoded signature of the JWT token.
    def encoded_signature
      @encoded_signature ||= ::JWT::Base64.url_encode(signature)
    end

    # Returns the decoded header of the JWT token.
    #
    # @return [Hash] the header of the JWT token.
    attr_reader :header

    # Returns the encoded header of the JWT token.
    #
    # @return [String] the encoded header of the JWT token.
    def encoded_header
      @encoded_header ||= ::JWT::Base64.url_encode(JWT::JSON.generate(header))
    end

    # Returns the payload of the JWT token.
    #
    # @return [Hash] the payload of the JWT token.
    attr_reader :payload

    # Returns the encoded payload of the JWT token.
    #
    # @return [String] the encoded payload of the JWT token.
    def encoded_payload
      @encoded_payload ||= ::JWT::Base64.url_encode(JWT::JSON.generate(payload))
    end

    # Returns the signing input of the JWT token.
    #
    # @return [String] the signing input of the JWT token.
    def signing_input
      @signing_input ||= [encoded_header, encoded_payload].join('.')
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    # @raise [JWT::EncodeError] if the token is not signed or other encoding issues
    def jwt
      @jwt ||= (@signature && [encoded_header, encoded_payload, encoded_signature].join('.')) || raise(::JWT::EncodeError, 'Token is not signed')
    end

    # Verifies the claims of the JWT token.
    #
    # @param options [Array] the options for verifying the claims.
    # @return [void]
    # @raise [JWT::DecodeError] if any claim is invalid.
    def verify_claims!(*options)
      Claims.verify!(self, *options)
    end

    # Checks if the claims of the JWT token are valid.
    #
    # @param options [Array] the options for verifying the claims.
    # @return [Boolean] true if the claims are valid, false otherwise.
    def valid_claims?(*options)
      claim_errors(*options).empty?
    end

    # Returns the errors in the claims of the JWT token.
    #
    # @param options [Array] the options for verifying the claims.
    # @return [Array<JWT::Claims::Error>] the errors in the claims of the JWT token.
    def claim_errors(*options)
      Claims.errors(self, *options)
    end

    # Verifies the signature of the JWT token.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @return [void]
    # @raise [JWT::VerificationError] if the signature verification fails.
    def verify_signature!(algorithm:, key:)
      return if valid_signature?(algorithm: algorithm, key: key)

      raise JWT::VerificationError, 'Signature verification failed'
    end

    # Checks if the signature of the JWT token is valid.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @return [Boolean] true if the signature is valid, false otherwise.
    def valid_signature?(algorithm:, key:)
      Array(JWA.resolve_and_sort(algorithms: algorithm, preferred_algorithm: header['alg'])).any? do |algo|
        Array(key).any? do |one_key|
          algo.verify(data: signing_input, signature: signature, verification_key: one_key)
        end
      end
    end

    # Signs the JWT token.
    #
    # @param algorithm [String, Object] the algorithm to use for signing.
    # @param key [String] the key to use for signing.
    # @return [void]
    # @raise [JWT::EncodeError] if the token is already signed or other problems when signing
    def sign!(algorithm:, key:)
      raise ::JWT::EncodeError, 'Token already signed' if @signature

      JWA.resolve(algorithm).tap do |algo|
        header.merge!(algo.header)
        @signature = algo.sign(data: signing_input, signing_key: key)
      end
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    alias to_s jwt
  end

  class EncodedToken
    attr_reader :jwt

    # Initializes a new EncodedToken instance.
    #
    # @param jwt [String] the encoded JWT token.
    def initialize(jwt)
      raise ArgumentError 'Provided JWT must be a String' unless jwt.is_a?(String)

      @jwt = jwt
      @encoded_header, @encoded_payload, @encoded_signature = jwt.split('.')
      @signing_input = [encoded_header, encoded_payload].join('.')
    end

    # Returns the decoded signature of the JWT token.
    #
    # @return [String] the decoded signature of the JWT token.
    def signature
      @signature ||= ::JWT::Base64.url_decode(encoded_signature || '')
    end

    # Returns the encoded signature of the JWT token.
    #
    # @return [String] the encoded signature of the JWT token.
    attr_reader :encoded_signature

    # Returns the decoded header of the JWT token.
    #
    # @return [Hash] the header of the JWT token.
    def header
      @header ||= parse_and_decode(@encoded_header)
    end

    # Returns the encoded header of the JWT token.
    #
    # @return [String] the encoded header of the JWT token.
    attr_reader :encoded_header

    # Returns the payload of the JWT token.
    #
    # @return [Hash] the payload of the JWT token.
    def payload
      @payload ||= parse_and_decode(encoded_payload)
    end

    # Returns the encoded payload of the JWT token.
    #
    # @return [String] the encoded payload of the JWT token.
    attr_reader :encoded_payload

    # Returns the signing input of the JWT token.
    #
    # @return [String] the signing input of the JWT token.
    attr_reader :signing_input

    # Verifies the claims of the JWT token.
    #
    # @param options [Array] the options for verifying the claims.
    # @return [void]
    # @raise [JWT::DecodeError] if any claim is invalid.
    def verify_claims!(*options)
      Claims.verify!(self, *options)
    end

    # Checks if the claims of the JWT token are valid.
    #
    # @param options [Array] the options for verifying the claims.
    # @return [Boolean] true if the claims are valid, false otherwise.
    def valid_claims?(*options)
      claim_errors(*options).empty?
    end

    # Returns the errors in the claims of the JWT token.
    #
    # @param options [Array] the options for verifying the claims.
    # @return [Array<JWT::Claims::Error>] the errors in the claims of the JWT token.
    def claim_errors(*options)
      Claims.errors(self, *options)
    end

    # Verifies the signature of the JWT token.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @return [void]
    # @raise [JWT::VerificationError] if the signature verification fails.
    def verify_signature!(algorithm:, key:)
      return if valid_signature?(algorithm: algorithm, key: key)

      raise JWT::VerificationError, 'Signature verification failed'
    end

    # Checks if the signature of the JWT token is valid.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @return [Boolean] true if the signature is valid, false otherwise.
    def valid_signature?(algorithm:, key:)
      Array(JWA.resolve_and_sort(algorithms: algorithm, preferred_algorithm: header['alg'])).any? do |algo|
        Array(key).any? do |one_key|
          algo.verify(data: signing_input, signature: signature, verification_key: one_key)
        end
      end
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    alias to_s jwt

    private

    def parse_and_decode(segment)
      JWT::JSON.parse(::JWT::Base64.url_decode(segment))
    rescue ::JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
