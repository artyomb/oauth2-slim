# frozen_string_literal: true

module DomainPayload
  INPUT_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789.-'
  OUTPUT_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
  VERSION = 'D'
  MAX_INPUT_LENGTH = OUTPUT_ALPHABET.length

  INPUT_INDEX = INPUT_ALPHABET.chars.each_with_index.to_h.freeze
  OUTPUT_INDEX = OUTPUT_ALPHABET.chars.each_with_index.to_h.freeze

  class << self
    def encode(domain)
      value = normalize(domain)

      number = 0
      value.each_char do |char|
        number = number * INPUT_ALPHABET.length + input_digit(char)
      end

      "#{VERSION}#{OUTPUT_ALPHABET[value.length - 1]}#{encode_number(number)}"
    end

    def decode(payload)
      value = payload.to_s
      raise ArgumentError, 'Invalid payload version' unless value.start_with?(VERSION)
      raise ArgumentError, 'Payload is too short' if value.length < 2

      length = output_digit(value[1]) + 1
      number = decode_number(value[2..].to_s)

      decoded = Array.new(length)
      (length - 1).downto(0) do |index|
        decoded[index] = INPUT_ALPHABET[number % INPUT_ALPHABET.length]
        number /= INPUT_ALPHABET.length
      end

      raise ArgumentError, 'Payload overflow' unless number.zero?

      decoded = decoded.join
      raise ArgumentError, 'Payload is not canonical' unless encode(decoded) == value

      decoded
    end

    private

    def normalize(domain)
      value = domain.to_s.downcase.delete_suffix('.')
      raise ArgumentError, 'Domain is empty' if value.empty?
      raise ArgumentError, 'Domain is too long' if value.length > MAX_INPUT_LENGTH

      value.each_char { |char| input_digit(char) }
      value
    end

    def encode_number(number)
      result = +''
      while number.positive?
        result << OUTPUT_ALPHABET[number % OUTPUT_ALPHABET.length]
        number /= OUTPUT_ALPHABET.length
      end
      result.reverse
    end

    def decode_number(value)
      value.each_char.reduce(0) do |number, char|
        number * OUTPUT_ALPHABET.length + output_digit(char)
      end
    end

    def input_digit(char)
      INPUT_INDEX.fetch(char) { raise ArgumentError, "Invalid domain character: #{char}" }
    end

    def output_digit(char)
      OUTPUT_INDEX.fetch(char) { raise ArgumentError, "Invalid payload character: #{char}" }
    end
  end
end

if $PROGRAM_NAME == __FILE__
  def assert(condition, message)
    raise "Self-test failed: #{message}" unless condition
  end

  def assert_raises(message)
    yield
    raise "Self-test failed: #{message}"
  rescue ArgumentError
    true
  end

  expected_payloads = {
    'short-cloud.ru' => 'DNBU8g9Azj4Yn3y',
    'one.long.very-long.domain.com' => 'DcBuPV7cYinRMEaxT_iiC_x28_SY'
  }

  expected_payloads.each do |domain, payload|
    assert(DomainPayload.encode(domain) == payload, "encodes #{domain}")
    assert(DomainPayload.decode(payload) == domain, "decodes #{domain}")
  end

  %w[a z aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa].each do |domain|
    assert(DomainPayload.decode(DomainPayload.encode(domain)) == domain, "round-trips #{domain}")
  end

  assert(DomainPayload.decode(DomainPayload.encode('Example.COM.')) == 'example.com', 'normalizes case and trailing dot')
  assert(DomainPayload.encode('a') == 'DA', 'encodes zero value without redundant body')
  assert(DomainPayload.encode('z' * 64).length <= 64, 'packs 64 max-value domain chars into Telegram limit')

  assert_raises('rejects empty domain') { DomainPayload.encode('') }
  assert_raises('rejects invalid domain chars') { DomainPayload.encode('example_com') }
  assert_raises('rejects too long domain') { DomainPayload.encode('a' * 65) }
  assert_raises('rejects invalid payload version') { DomainPayload.decode('XKCKzYY-aJzy') }
  assert_raises('rejects non-canonical payload') { DomainPayload.decode('DAA') }

  puts 'DomainPayload self-tests passed'
end
