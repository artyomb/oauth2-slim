require 'async/semaphore'
# require_relative 'src/config_dsl'
require 'yaml'

LOGGER.warn 'TELEGRAM TOKEN, CHAT_ID not set' unless ENV['TELEGRAM_BOT_TOKEN'] && ENV['TELEGRAM_CHAT_ID']

# CONFIG = ConfigDSL.load "#{__dir__}/listener_config.rb"
# LOGGER.info CONFIG.to_yaml
