# ActsAsEncrypted
require 'acts_as_encrypted/engine'

module ActsAsEncrypted
  
  class ConfigurationError < StandardError; end
  
  def self.included(base)
    base.extend ActMacro
  end

  module ClassMethods
    #Set up encryption on a column. Expects two extra columns 
    #_to be present in the database: col_keyid and col_iv.
    #_The specific key used is stored in the col_keyid column,
    #_and the IV associated with the current ciphertext is 
    #_stored in the col_iv column.
    #
    # == Override key family ==
    #
    #Use the :family key to override the key family for this 
    #_column:
    #
    # encrypts :ccnum, :family => :ccnum
    #
    # == Leave some part of plaintext unencrypted ==
    #
    #All other keys will be interpreted as keys to parts of the
    #_plaintext to leave unencrypted. The value for each should be
    #_a Proc which given the plaintext returns the plaintext to 
    #_be stored unencrypted in the column derived from the key:
    # 
    # encrypts :ccnum, :lastfour => lambda { |cc| cc[-4,4] }
    #
    #would leave the last four digits of :ccnum unencrypted in 
    #_the column ccnum_lastfour.
    #
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
      else
        unless f = family
          raise ConfigurationError.new("no key family defined for column #{column}")
        else
          encrypts_cols[column] = f
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
      @decrypts ||= Hash.new
      encrypts_cols.each do |col, f|
        if self[col]
          # keep a copy of the plaintext to avoid tainting
          plaintext = self[col]
          if self["#{f}_keyid"]
            # encrypt with same key as before if we have one
            log_operation(col, "encrypt")
            self[col], self["#{col}_iv"], self["#{f}_keyid"] = ActsAsEncrypted::Engine.engine.encrypt(f, self["#{f}_keyid"], self[col])
          else
            # encrypt with current key
            log_operation(col, "encrypt")
            self[col], self["#{col}_iv"], self["#{f}_keyid"] = ActsAsEncrypted::Engine.engine.encrypt(f, nil, self[col])
          end
          # save the plaintext
          @decrypts[col] = plaintext
        end
      end
    end

    def decrypt
      @decrypts ||= Hash.new
      encrypts_cols.each do |col, f|
        if @decrypts && @decrypts[col]
          self[col] = @decrypts[col]
        else
          if self[col]
            # decrypt with specific keyid stored in db
            log_operation(col, "decrypt")
            self[col] = ActsAsEncrypted::Engine.engine.decrypt(f, self["#{f}_keyid"], self["#{col}_iv"], self[col])
            @decrypts[col] = self[col]
          end
        end
      end
    end
    
    def reencrypt
      # for each encrypted column, run encryption and store the
      # result into the same column.
      encrypts_cols.each do |col, f|
        if self[col]
          # encrypt with current key
          log_operation(col, "encrypt")
          self[col], self["#{col}_iv"], self["#{f}_keyid"] = ActsAsEncrypted::Engine.engine.encrypt(f, nil, self[col])
        end
      end
      decrypt
    end

    def after_find
      # engage after_find callback, see:
      # http://api.rubyonrails.org/classes/ActiveRecord/Callbacks.html
    end

    private 
    def log_operation(column, op)
      if ActiveRecord::Base.colorize_logging
        message = "  \e[4;32;1m%s.%s %s\e[0m" % [self.class.to_s, column, op]
      else
        message = "%s.%s %s" % [self.class.to_s, column, op]
      end
      logger.info(message)
    end
  end
    
  class ActiveRecord::Base
    def write_attribute_with_tainting(attr_name, value)
      if encrypts_cols.include?(attr_name)
        @decrypts[attr_name] = nil
      end
      write_attribute_without_tainting(attr_name, value)
    end
  end

  module ActMacro
    # acts_as_encrypted is the ActiveRecord model-class macro, which
    # adds transparent data encryption to the model.
    # 
    # May be called with a symbol argument, which will be the default
    # key family used for encryption.
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

      alias_method_chain :write_attribute, :tainting
    end
    
  end
end
