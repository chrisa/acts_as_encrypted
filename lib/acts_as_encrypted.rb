# ActsAsEncrypted
require 'acts_as_encrypted/engine'

module ActsAsEncrypted

  def self.included(base)
    base.extend ActMacro
  end

  module ClassMethods
    def encrypts(column, *opts)
      if opts = opts.shift
        # handle overridden key family
        if opts[:family]
          encrypts_cols[column] = opts[:family]
          opts.delete(:family)
        else
          encrypts_cols[column] = family
        end
        # handle left-unencrypted columns
        opts.each do |key, value|
          if value.respond_to? :send
            unencrypted[column] = { 'column' => key, 'proc' => value }
          end
        end
      end
    end
  end
  
  module InstanceMethods
    def encrypt
      # for each left-unencrypted column set up, run the proc
      # on the column value and store the result into the 
      # left-unenc column.
      unencrypted.each do |key, unenc|
        if self[key]
          self["#{key}_#{unenc['column']}"] = unenc['proc'].call(self[key])
        end
      end

      # for each encrypted column, run encryption and store the
      # result into the same column.
      encrypts_cols.each do |col, f|
        if self[col]
          if self["#{f}_start"] && self["#{f}_start"] > 0
            # encrypt with same key as before if we have one
            self[col], self["#{col}_iv"], self["#{f}_start"] = ActsAsEncrypted::Engine.engine.encrypt(f, self["#{f}_start"], self[col])
          else
            # encrypt with current key
            self[col], self["#{col}_iv"], self["#{f}_start"] = ActsAsEncrypted::Engine.engine.encrypt(f, nil, self[col])
          end
        end
      end
    end

    def decrypt
      encrypts_cols.each do |col, f|
        if self[col]
          # decrypt with specific key start stored in db
          self[col] = ActsAsEncrypted::Engine.engine.decrypt(f, self["#{f}_start"], self["#{col}_iv"], self[col])
        end
      end
    end

    def reencrypt
      # for each encrypted column, run encryption and store the
      # result into the same column.
      encrypts_cols.each do |col, f|
        if self[col]
          # encrypt with current key
          self[col], self["#{col}_iv"], self["#{f}_start"] = ActsAsEncrypted::Engine.engine.encrypt(f, nil, self[col])
        end
      end
      decrypt
    end

    def after_find
      # engage after_find callback, see:
      # http://api.rubyonrails.org/classes/ActiveRecord/Callbacks.html
    end
  end

  module ActMacro
    def acts_as_encrypted(family=nil)
      self.extend(ClassMethods)
      write_inheritable_attribute :family, family
      class_inheritable_reader :family
      self.send(:include, ActsAsEncrypted::InstanceMethods)

      before_save      :encrypt
      after_save       :decrypt
      after_initialize :decrypt
      after_find       :decrypt

      write_inheritable_attribute :encrypts_cols, Hash.new
      write_inheritable_attribute :unencrypted, Hash.new
      class_inheritable_accessor :encrypts_cols
      class_inheritable_accessor :unencrypted
    end
  end
  
end
