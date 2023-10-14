# frozen_string_literal: true

module JWT
  def self.gem_version
    Gem::Version.new VERSION::STRING
  end

  module VERSION
    # major version
    MAJOR = 3
    # minor version
    MINOR = 0
    # tiny version
    TINY  = 0
    # alpha, beta, etc. tag
    PRE   = 'alpha.1'

    # Build version string
    STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')
  end

  def self.openssl_3?
    return false if OpenSSL::OPENSSL_VERSION.include?('LibreSSL')

    3 * 0x10000000 <= OpenSSL::OPENSSL_VERSION_NUMBER
  end

  def self.rbnacl?
    defined?(::RbNaCl)
  end

  def self.openssl_3_hmac_empty_key_regression?
    openssl_3? && openssl_version <= ::Gem::Version.new('3.0.0')
  end

  def self.openssl_version
    @openssl_version ||= ::Gem::Version.new(OpenSSL::VERSION)
  end
end
