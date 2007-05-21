# ActsAsEncrypted
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
      unencrypted.each do |key, unenc|
        self["#{key}_#{unenc['column']}"] = unenc['proc'].call(self[key])
      end
      encrypts_cols.each_key do |col|
        self[col] = "encrypted: #{self[col]}"
      end
    end

    def decrypt
      encrypts_cols.each_key do |col|
        self[col] = "decrypted: #{self[col]}"
      end
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
