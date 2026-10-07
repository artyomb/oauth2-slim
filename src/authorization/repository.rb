# frozen_string_literal: true

require 'sequel'
require 'time'
require_relative 'validation'

Sequel.extension :pg_json_ops

module Authorization
  class PolicyRepository
    attr_reader :db

    def initialize(db)
      @db = db
      db.extension :pg_json
      @model = Class.new(Sequel::Model(db[:authorization_policies]))
    end

    def user(id)
      db[:oauth_users].where(id:, deleted_at: nil).first
    end

    def find(id)
      record = @model[id]
      raise Error.new('Policy not found', status: 404, code: 'not_found') unless record

      serialize(record)
    end

    def list(params)
      dataset = @model.select(*(@model.columns - [:definition]))
      dataset = dataset.where(Sequel.ilike(:name, "%#{dataset.escape_like(params['search'])}%")) if params['search'].is_a?(String) && !params['search'].empty?
      { 'type' => :policy_type, 'resource_type' => :resource_type }.each do |key, column|
        dataset = dataset.where(column => Validation.selector(params[key], key)) if params.key?(key) && params[key] != ''
      end
      if params.key?('active') && params['active'] != ''
        raise Error.new('active must be true or false', status: 400) unless %w[true false].include?(params['active'])

        dataset = dataset.where(active: params['active'] == 'true')
      end
      dataset = dataset.where(Sequel.pg_jsonb_op(:actions).contains([Validation.selector(params['action'], 'action')])) if params.key?('action') && params['action'] != ''
      db.transaction(isolation: :repeatable, read_only: true) do
        result = page(dataset.order(:name, :id), params) { |record| serialize(record) }
        ids = result[:data].map { |record| record[:id] }
        counts = db[:user_policies].where(policy_id: ids).group_and_count(:policy_id).to_hash(:policy_id, :count)
        result[:data].each { |record| record[:assignment_count] = counts.fetch(record[:id], 0) }
        result
      end
    end

    def create(attributes)
      serialize(@model.create(attributes))
    end

    def update(id, attributes, expected_revision:)
      db.transaction do
        record = locked_policy(id)
        check_revision(record, expected_revision)
        record.set(attributes.merge(revision: record[:revision] + 1, updated_at: Time.now.utc))
        record.save
        serialize(record)
      end
    end

    def delete(id, expected_revision:)
      db.transaction do
        record = locked_policy(id)
        check_revision(record, expected_revision)
        if record[:active] || db[:user_policies].where(policy_id: id).any?
          raise Error.new('Disable the policy and remove all assignments before deleting it', status: 409, code: 'deletion_conflict')
        end
        record.delete
      end
    end

    def assignments(id, params)
      db.transaction(isolation: :repeatable, read_only: true) do
        find(id)
        dataset = db[:user_policies].where(policy_id: id).join(:oauth_users, id: :user_id)
        dataset = dataset.select(Sequel[:oauth_users][:id], :login, :name, Sequel[:user_policies][:created_at]).order(:login, Sequel[:oauth_users][:id])
        page(dataset, params) { |record| record.merge(type: 'user', created_at: record[:created_at].iso8601) }
      end
    end

    def users(params)
      dataset = db[:oauth_users].where(deleted_at: nil)
      if params['search'].is_a?(String) && !params['search'].empty?
        search = "%#{dataset.escape_like(params['search'])}%"
        dataset = dataset.where(Sequel.|(Sequel.ilike(:login, search), Sequel.ilike(:name, search)))
      end
      db.transaction(isolation: :repeatable, read_only: true) do
        page(dataset.select(:id, :login, :name).order(:login, :id), params) { |record| record }
      end
    end

    def assign(id, user_id, remove: false)
      db.transaction do
        locked_policy(id)
        bindings = db[:user_policies]
        if remove
          bindings.where(policy_id: id, user_id:).delete
        else
          subject = db[:oauth_users].where(id: user_id, deleted_at: nil).for_update.first
          raise Error.new('User not found', status: 404, code: 'not_found') unless subject

          bindings.insert_conflict.insert(policy_id: id, user_id:)
        end
      end
    end

    def effective(subject_id, resource_type:, action:)
      db.transaction(isolation: :repeatable, read_only: true) do
        raise Error.new('User no longer exists', status: 401, code: 'unauthenticated') unless user(subject_id)

        policy_ids = db[:user_policies].where(user_id: subject_id).select(:policy_id)
        records = @model.where(id: policy_ids, active: true, resource_type:)
        records = records.where(Sequel.pg_jsonb_op(:actions).contains([action])).order(:priority, :id)
        records.all.map do |record|
          serialize(record).merge(assigned_via: [{ type: 'user', id: subject_id }])
        end
      end
    end

    private

    def locked_policy(id)
      record = @model.where(id:).for_update.first
      raise Error.new('Policy not found', status: 404, code: 'not_found') unless record

      record
    end

    def check_revision(record, expected)
      return if record[:revision] == expected

      raise Error.new('Policy changed; reload and review your edits before saving', status: 409, code: 'stale_revision', current_revision: record[:revision])
    end

    def serialize(record)
      values = record.values.dup
      values[:type] = values.delete(:policy_type)
      values[:actions] = values[:actions].to_a
      values[:definition] = values[:definition].to_h if values.key?(:definition)
      %i[created_at updated_at].each { |field| values[field] = values[field].iso8601(6) }
      values
    end

    def page(dataset, params)
      pagination = Validation.pagination(params)
      { **pagination, total: dataset.count, data: dataset.limit(pagination[:limit], pagination[:offset]).all.map { |record| yield record } }
    end
  end
end
