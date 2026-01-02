require 'i18n'

I18n.load_path = Dir["#{__dir__}/locales/*.yml"]
I18n.default_locale = :en
I18n.available_locales = Dir["#{__dir__}/locales/*.yml"].map { File.basename(_1, '.yml').to_sym }
I18n.backend.load_translations
