require 'ed25519'
require 'jwt'
require 'jwt/eddsa'

# {"USER_AGENT" => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
# "ACCEPT" => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
# "ACCEPT_ENCODING" => "gzip, deflate, br, zstd",
# "ACCEPT_LANGUAGE" => "en-US,en;q=0.9,ru;q=0.8,zh-CN;q=0.7,zh;q=0.6",
# "PRIORITY" => "u=0, i",
# "REFERER" => "https://gis-master.ru/asd/authorize",
# "REQUEST_PATH" => "/authorize",
# "SEC_CH_UA" => "\"Not;A=Brand\";v=\"99\", \"Google Chrome\";v=\"139\", \"Chromium\";v=\"139\"", "SEC_CH_UA_MOBILE" => "?0",
# "SEC_CH_UA_PLATFORM" => "\"Linux\"", "SEC_FETCH_DEST" => "document", "SEC_FETCH_MODE" => "navigate",
# "SEC_FETCH_SITE" => "same-origin", "SEC_FETCH_USER" => "?1", "UPGRADE_INSECURE_REQUESTS" => "1",
# "X_CUSTOM_REQUEST_HEADER" => "test", "X_FORWARDED_FOR" => "10.0.0.2",
# "X_FORWARDED_HOST" => "gis-master.ru", "X_FORWARDED_PORT" => "443",
# "X_FORWARDED_PROTO" => "https", "X_FORWARDED_SERVER" => "c880f60752af", "X_REAL_IP" => "10.0.0.2",
# "X_SHORT_AGENT" => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
# "X_SHORT_PATH" => "/authorize", "X_SHORT_PATH2" => "/authorize",
# "HOST" => "gis-master.ru"}

message = "notam-cloud.ru|#{Time.now.to_i}"
signing_key = Ed25519::SigningKey.generate
p signing_key
signature = signing_key.sign(message)
hex_signature = signature.unpack('H*').first
p hex_signature
p hex_signature.size


verify_key = signing_key.verify_key
p verify_key.verify(signature, message)


access_token = JWT.encode({iss: 'test'}, signing_key, 'EdDSA')
decoded = JWT.decode(access_token, signing_key.verify_key, true, { algorithm: 'EdDSA' }).first
p decoded


signature_key_bytes = signing_key.to_bytes.unpack1('H*')
puts "signature_key_bytes: #{signature_key_bytes}"
verify_key_bytes = verify_key.to_bytes.unpack1('H*')
puts "verify_key_bytes: #{verify_key_bytes}"

signing_key = Ed25519::SigningKey.new([signature_key_bytes].pack('H*'))
verify_key  = Ed25519::VerifyKey.new([verify_key_bytes].pack('H*'))

signature_hex = 'c3f96dd300cecc2098b32c51bd489776d39034b0a739b76ab11945f48d310363'
verify_hex = 'ef526ffa86fd1ff339843cea35ccead0d113c02c31c2518d0f92b85d9dabfd21'

signing_key = Ed25519::SigningKey.new([signature_hex].pack('H*'))
verify_key  = Ed25519::VerifyKey.new([verify_hex].pack('H*'))

signature = signing_key.sign(message)
hex_signature = signature.unpack('H*').first
puts "#{message}|#{hex_signature}"