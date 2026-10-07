# frozen_string_literal: true

# Shares the DB-mode bootstrap and applies only pending authorization migrations.
ENV['FORWARD_OAUTH_AUTH_URL'] ||= '/authorize'
raise 'USERS_DB_URL is required' if ENV['USERS_DB_URL'].to_s.empty?

require_relative '../auth/db_user_auth'
puts 'User schema and authorization migrations are current.'
