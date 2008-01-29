require 'acts_as_encrypted/keystore'
require 'acts_as_encrypted/engine/local'
require 'acts_as_encrypted/engine/remote'
require 'acts_as_encrypted/engine/remote_http'

module ActsAsEncrypted

  class CryptoConfigError < StandardError; end
  class CryptoFailureError < StandardError; end

  class Engine
    
    # Sets the engine class. Possible values are 'local' for an engine
    # which directly loads and decrypts the keystore, or 'remote' for
    # an engine which contacts a remote encryption daemon over drbssl.
    def self.engine=(engine)
      begin
        @@engine_class = ActsAsEncrypted::Engine.const_get(engine.to_s.camelize)
      rescue NameError
        raise CryptoConfigError.new("no engine for :#{engine.to_s}")
      end
    end

    # Sets the configuration hash for the Engine.
    def self.config=(config)
      @@engine_class.validate config
      @@config = config
    end
    
    # Returns an instance of the engine.
    def self.engine
      @@engine ||= @@engine_class.new(@@config)
    end

    # Causes the next call to engine to return a newly-loaded engine,
    # which will re-read the keystore.
    def self.reload
      @@engine = nil
    end

    # Engines can override this to perform config validation at startup
    # (should throw CryptoConfigError)
    def self.validate(config)
    end
  end

end
