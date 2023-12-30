# frozen_string_literal: true

require 'rspec'
require 'simplecov'
require 'jwt'

require_relative 'spec_support/test_keys'

puts "OpenSSL::VERSION: #{OpenSSL::VERSION}"
puts "OpenSSL::OPENSSL_VERSION: #{OpenSSL::OPENSSL_VERSION}"
puts "OpenSSL::OPENSSL_LIBRARY_VERSION: #{OpenSSL::OPENSSL_LIBRARY_VERSION}\n\n"

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
  config.include(SpecSupport::TestKeys)
  config.before(:example) { JWT.configuration.reset! }
  config.run_all_when_everything_filtered = true
  config.filter_run :focus
  config.order = 'random'
end
