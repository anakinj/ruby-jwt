# frozen_string_literal: true

module JWT
  class Token
    attr_reader :value, :decoder

    def initialize(value:, decoder:)
      @value = value
      @decoder = decoder
    end

    def segments
      @segments ||= value.split('.')
    end

    def segment_count
      segments.size
    end

    def raw_payload
      segments[1]
    end

    def raw_signature
      segments[2]
    end

    def raw_header_and_payload
      segments.first(2).join('.')
    end

    def raw_header
      segments.first
    end

    def header
      decoder.decode(type: :header, value: raw_header)
    end

    def signature
      decoder.decode(type: :signature, value: raw_signature) if raw_signature
    end

    def payload
      decoder.decode(type: :payload, value: raw_payload)
    end

    def alg_in_header
      header['alg']
    end
  end
end
