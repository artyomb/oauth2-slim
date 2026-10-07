# frozen_string_literal: true

require 'sequel'
Sequel.extension :migration

module Authorization
  module Schema
    def self.migrate(db)
      db.extension :pg_json
      db.transaction do
        db.get(Sequel.function(:pg_advisory_xact_lock, 1_094_865_236))
        Sequel::Migrator.run(db, File.join(__dir__, 'migrations'), table: :authorization_schema_info)
      end
    end
  end
end
