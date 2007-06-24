require 'drb'
require 'drb/ssl'
require 'openssl'
require 'base64'
require 'acts_as_encrypted/keystore'

module ActsAsEncrypted

  class CryptoFailureError < StandardError; end

  class Engine
    
    # Sets the engine class. Possible values are 'local' for an engine
    # which directly loads and decrypts the keystore, or 'remote' for
    # an engine which contacts a remote encryption daemon over drbssl.
    def self.engine=(engine)
      if (engine == 'local')
        @@engine_class = ActsAsEncrypted::Engine::Local
      elsif (engine == 'remote')
        @@engine_class = ActsAsEncrypted::Engine::Remote
      else
        raise "no engine for #{engine}"
      end
    end

    # Sets the configuration hash for the Engine.
    def self.config=(config)
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
  end

  class Engine::Local < Engine
    
    def initialize(config)
      # server config -- required to decrypt keystore
      @keystore = ActsAsEncrypted::Keystore.new(config)
    end

    # The encryption method. Encrypts the given plaintext with a key
    # from the given family, either the current key if start is nil,
    # or the key specified as start. 
    # 
    # Returns the ciphertext and IV as base64 encoded strings, and the
    # key used, whether it was specified or selected as the current
    # key.
    # 
    # Can raise a CryptoFailureError, in case of failed encryption.
    def encrypt(family, start, plaintext)
      if start 
        key = @keystore.get_key(family, start)
      else
        key, start = @keystore.get_current_key(family)
      end
      begin
        cipher = get_cipher
        cipher.encrypt(key)
        iv = cipher.random_iv
        ciphertext = cipher.update(plaintext)
        ciphertext << cipher.final
      rescue
        raise CryptoFailureError.new
      end
      return Base64.encode64(ciphertext).chomp, Base64.encode64(iv).chomp, start
    end
    
    # The decryption method. Decrypts the given ciphertext (as a
    # base64 encoded string) with the specified key family and start,
    # using the specified IV (also base64 encoded string).
    #
    # Returns the plaintext, or raises a CryptoFailureError.
    def decrypt(family, start, iv, ciphertext)
      if start 
        key = @keystore.get_key(family, start)
      else
        key, start = @keystore.get_current_key(family)
      end
      begin
        cipher = get_cipher
        cipher.decrypt(key)
        cipher.iv = Base64.decode64(iv)
        plaintext = cipher.update(Base64.decode64(ciphertext))
        plaintext << cipher.final
      rescue
        raise CryptoFailureError.new
      end
      return plaintext
    end

    private 
    # Returns the cipher to be used for encryption and decryption of
    # model data.
    def get_cipher
      OpenSSL::Cipher::Cipher.new('AES-256-CBC')      
    end

  end

  class Engine::Remote < Engine

    def initialize(config)
      there = "drbssl://#{config[:server]}"
      DRb.start_service nil, nil, config
      @service = DRbObject.new nil, there
    end

    def encrypt(family, start, plaintext)
      @service.encrypt(family, start, plaintext)
    end
    
    def decrypt(family, start, iv, ciphertext)
      @service.decrypt(family, start, iv, ciphertext)
    end

  end
end
