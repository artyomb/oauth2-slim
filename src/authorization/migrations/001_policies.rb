# frozen_string_literal: true

Sequel.migration do
  change do
    create_table(:authorization_policies) do
      primary_key :id
      String :name, null: false, size: 200
      String :description, text: true, null: false, default: ''
      String :policy_type, null: false
      String :resource_type, null: false, size: 200
      column :actions, :jsonb, null: false
      String :effect, null: false
      TrueClass :active, null: false, default: false
      Float :priority, null: false, default: 0
      column :definition, :jsonb, null: false
      Integer :schema_version, null: false, default: 1
      Integer :revision, null: false, default: 1
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :updated_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      check(Sequel.lit("effect IN ('allow', 'deny')"))
      check(Sequel.lit('revision > 0 AND schema_version > 0'))
      check(Sequel.lit("jsonb_typeof(definition) = 'object'"))
      check(Sequel.lit("jsonb_typeof(actions) = 'array' AND jsonb_array_length(actions) > 0"))
      index [:resource_type, :active, :policy_type]
      index :actions, type: :gin
    end

    create_table(:user_policies) do
      foreign_key :user_id, :oauth_users, null: false, on_delete: :cascade
      foreign_key :policy_id, :authorization_policies, null: false, on_delete: :restrict
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      primary_key [:user_id, :policy_id]
      index :policy_id
    end
  end
end
