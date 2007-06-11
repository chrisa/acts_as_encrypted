require 'drb'
require 'drb/ssl'
require 'acts_as_encrypted/keystore'

module ActsAsEncrypted

  class Engine
    def self.engine=(engine)
      if (engine == 'local')
        @@engine_class = ActsAsEncrypted::Engine::Local
      elsif (engine == 'remote')
        @@engine_class = ActsAsEncrypted::Engine::Remote
      else
        raise "no engine for #{engine}"
      end
    end

    def self.config=(config)
      @@config = config
    end
    
    def self.engine
      @@engine_class.new(@@config)
    end
  end

  class Engine::Local < Engine
    
    def initialize(config)
      # server config -- required to decrypt keystore
      @keystore = ActsAsEncrypted::Keystore.new(config)
    end

    def get_cipher
      OpenSSL::Cipher::Cipher.new('AES-256-CBC')      
    end

    def encrypt(family, plaintext)
      key = @keystore.get_current_key(family)
      cipher = get_cipher
      cipher.encrypt(key)
      iv = cipher.random_iv
      ciphertext = cipher.update(plaintext)
      ciphertext << cipher.final
      return ciphertext, iv
    end
    
    def decrypt(family, iv, ciphertext)
      key = @keystore.get_current_key(family)
      cipher = get_cipher
      cipher.decrypt(key)
      cipher.iv = iv 
      plaintext = cipher.update(ciphertext)
      plaintext << cipher.final
      return plaintext
    end

  end

  class Engine::Remote < Engine

    def initialize(config)
      there = 'drbssl://localhost:3456'
      DRb.start_service nil, nil, config
      @service = DRbObject.new nil, there
    end

    def encrypt(family, plaintext)
      @service.encrypt(family, plaintext)
    end
    
    def decrypt(family, iv, ciphertext)
      @service.decrypt(family, iv, ciphertext)
    end

  end
end
