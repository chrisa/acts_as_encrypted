require 'drb'
require 'drb/ssl'
require 'openssl'
require 'base64'
require 'acts_as_encrypted/keystore'

module ActsAsEncrypted

  class CryptoFailureError < StandardError; end

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
      @@engine ||= @@engine_class.new(@@config)
    end

    def self.reload
      @@engine = nil
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
