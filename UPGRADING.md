# Upgrading

This document describes breaking changes in behavior and api for major version of this gem.

## Upgrading to ruby-jwt 3.0.0

### Base64 decoding

As of 3.0.0 the gem is using the Ruby stdlib base64 decoding that conforms to RFC 4648.This means for example that tokens passed to decoding cannot contain trailing spaces and newlines.

Also the module `::JWT::Base64` has been removed.