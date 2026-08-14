#!/usr/bin/env ruby
# frozen_string_literal: true
require 'net/http'
require 'json'
require 'uri'
require 'ed25519'
require 'base64'
require 'rack'
require 'zlib'
require_relative '../auth/domain_payload'
require_relative '../auth/log_safety'

USERS_KEYS = %i[tg_id login scopes]

File.readlines("#{__dir__}/.secrets").each do |line|
  key, value = line.split('=')
  ENV[key.strip] = value.strip
end

# scope=asd.ru&url=http://asd.ru/authorize
# https://t.me/slim_auth_bot?start=c2...==
# The parameter can be up to 64 characters long.
TOKEN = ENV.fetch('TELEGRAM_TOKEN')
API   = "https://api.telegram.org/bot#{TOKEN}".freeze
SIGNING_HEX = ENV['SIGNING_KEY']
SIGNING_KEY = Ed25519::SigningKey.new([SIGNING_HEX].pack('H*'))
AUDIT_CHAT_ID = ENV.fetch('AUDIT_CHAT_ID', nil)
# ruby -red25519 -e 'k=Ed25519::SigningKey.generate; puts "SIGNING_KEY=#{k.to_bytes.unpack1(%q{H*})}"; puts "AUTH_VERIFY_KEY=#{k.verify_key.to_bytes.unpack1(%q{H*})}"'

def api_get(path, params = {})
  uri = URI("#{API}/#{path}")
  uri.query = URI.encode_www_form(params) unless params.empty?
  JSON.parse(Net::HTTP.get(uri))
end

def api_post(path, payload = {})
  uri = URI("#{API}/#{path}")
  req = Net::HTTP::Post.new(uri)
  req['Content-Type'] = 'application/json'
  req.body = JSON.dump(payload)
  Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
    JSON.parse(http.request(req).body)
  end
end

def html(value)
  Rack::Utils.escape_html(value.to_s)
end

def send_audit_log(text)
  return unless AUDIT_CHAT_ID

  api_post('sendMessage', chat_id: AUDIT_CHAT_ID, text:, parse_mode: 'HTML')
end

def telegram_name(from)
  [from['first_name'], from['last_name']].compact.join(' ')
end

def telegram_username(from)
  from['username'] ? "@#{from['username']}" : 'N/A'
end

def audit_line(label, value)
  "#{html(label)}: <code>#{html(value)}</code>"
end

def send_audit_event(status:, scope:, from:, user: nil, policy: nil, reason: nil)
  user_text = user ? "#{user[:login]} (TID: #{from['id']})" : "Unregistered (TID: #{from['id']})"
  lines = [
    audit_line('User', user_text),
    audit_line('Scope', scope),
    policy && audit_line('Policy', policy),
    reason && audit_line('Reason', reason),
    audit_line('Username', telegram_username(from)),
    audit_line('Name', telegram_name(from))
  ].compact

  send_audit_log("<b>#{html(status)}</b>\n#{lines.join("\n")}")
end

def printable_payload?(value)
  value.valid_encoding? && value.match?(/\A[[:print:][:space:]]+\z/)
end

def decode_base64_payload(value)
  padding = (4 - value.length % 4) % 4
  decoded = Base64.urlsafe_decode64(value + ('=' * padding))
  decoded.force_encoding(Encoding::UTF_8)
  return unless printable_payload?(decoded)

  decoded
rescue ArgumentError
  nil
end

def decode_scope_token(token)
  value = token.to_s.strip

  if value.start_with?(DomainPayload::VERSION)
    decoded = DomainPayload.decode(value) rescue nil
    return decoded if decoded
  end

  decode_base64_payload(value)
end

def extract_scope(text)
  input = text.to_s.strip

  token =
    case input
    when %r{\Ahttps?://t\.me/[^?]+\?start=([^&\s]+)\z}i
      Regexp.last_match(1)
    when %r{\A/?(?:start|auth|login)(?:@\w+)?\s+(\S+)\z}i
      Regexp.last_match(1)
    else
      input
    end

  decode_scope_token(token) || input
end

def policy_rules(user)
  user[:scopes].to_s.split(/[,\s]+/).map(&:strip).reject(&:empty?)
end

def policy_text(rules)
  rules.empty? ? '(empty)' : rules.join(', ')
end

def normalize_scope(value)
  value.to_s.downcase.delete_suffix('.')
end

def scope_allowed?(scope, rules)
  normalized_scope = normalize_scope(scope)

  rules.any? do |rule|
    normalized_rule = normalize_scope(rule)
    next true if normalized_rule == '*'

    if normalized_rule.start_with?('*.')
      suffix = normalized_rule[2..]
      normalized_scope != suffix && normalized_scope.end_with?(".#{suffix}")
    else
      normalized_scope == normalized_rule
    end
  end
end

offset = 0
loop do
  begin
    res = api_get('getUpdates', timeout: 25, offset: offset)
    res.fetch('result', []).each do |upd|
      offset = upd['update_id'] + 1
      msg = upd['message'] || upd['edited_message']
      next unless msg && msg['text']

      chat_id = msg['chat']['id']
      text    = msg['text']
      from    = msg['from']
      scope   = extract_scope(text)

      users = File.readlines("#{__dir__}/users.txt").map { |l| l.split(';').map(&:strip) }
                  .map { |r| USERS_KEYS.zip(r).to_h }

      user = users.find { |u| u[:tg_id].to_s == from['id'].to_s }
      unless user
        reply = "User not registered (TID: #{from['id']})"
        api_post('sendMessage', chat_id: chat_id, text: reply, parse_mode: 'HTML')

        send_audit_event(status: 'FAILED AUTH', scope:, from:, reason: 'User not registered')
        next
      end

      rules = policy_rules(user)
      unless scope_allowed?(scope, rules)
        reply = "Access denied for #{html(scope)}"
        api_post('sendMessage', chat_id: chat_id, text: reply, parse_mode: 'HTML')

        send_audit_event(status: 'FAILED AUTH', scope:, from:, user:, policy: policy_text(rules), reason: 'Scope is not allowed')
        next
      end

      message = "#{scope}|#{Time.now.to_i}|#{user[:login]}"

      signature = SIGNING_KEY.sign message
      hex_signature = signature.unpack('H*').first

      reply = Base64.urlsafe_encode64 Zlib::Deflate.deflate("#{message}|#{hex_signature}")

      api_post('sendMessage', chat_id: chat_id, text: "<code>#{reply}</code>", parse_mode: 'HTML')
      send_audit_event(status: 'SUCCESS AUTH', scope:, from:, user:, policy: policy_text(rules))
    end
  rescue => e
    $stderr.puts "Error: #{LogSafety.exception_message(e)}"
    sleep 2
  end
end
