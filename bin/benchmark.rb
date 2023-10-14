#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bundler/setup'
require 'benchmark'
require 'jwt'

hmac_secret = 'my$ecretK3y'

measure = Benchmark.measure do
  1000.times do
    token = JWT.encode({ pay: 'load' }, hmac_secret, 'HS256')
    JWT.decode(token, hmac_secret, true, { algorithm: 'HS256' })
  end
end

puts measure
