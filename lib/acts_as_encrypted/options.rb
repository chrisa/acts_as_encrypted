require 'optparse'
require 'ostruct'

module ActsAsEncrypted
  class Options

    def self.parse(args)
      options = OpenStruct.new
      options.cryptoroot = nil
      options.keystore = nil
      options.initializing = false
      options.server = 'localhost:3456'
      
      # parse options
      opts = OptionParser.new do |opts|
        opts.banner = 'Usage: keytool.rb [options]'
        opts.separator ""
        opts.separator "Options:"
        
        opts.on("-c", "--cryptoroot CRYPTOROOT", 
                "Where to find the keys directory") do |c|
          options.cryptoroot = c
        end

        opts.on("-k", "--keystore KEYSTORE",
                "Where to find the keystore file") do |k|
          options.keystore = k
        end
        
        opts.on("-i", "--[no-]init", 
                "Initialise a new keystore file") do |i|
          options.initializing = i
        end

        opts.on("-s", "--server SERVER",
                "Server host:port") do |s|
          options.server = s
        end
      end
      opts.parse!(args)

      # default paths here to avoid dependency on order of options
      if options.cryptoroot.nil?
        options.cryptoroot = File.expand_path('./keys')
      end
      if options.keystore.nil?
        options.keystore = "#{options.cryptoroot}/keystore"
      end
      
      # unqualified keystore names prepended with cryptoroot
      if /^\// !~ options.keystore
        options.keystore = "#{options.cryptoroot}/#{options.keystore}"
      end

      options
    end

  end
end
