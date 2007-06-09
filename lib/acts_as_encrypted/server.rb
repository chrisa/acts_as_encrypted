require File.expand_path(File.dirname(__FILE__) + "/keystore.rb")

module ActsAsEncrypted
  class Server

    def initialize(config)
      @config = config
      @config.delete(:SSLVerifyMode) # not relevant to us
      @keystore = ActsAsEncrypted::KeyStore.new(@config)
    end
    
    def ping
      "ok"
    end

    def encrypt(family, plaintext)
      key = find_key(family)
      cipher = get_cipher
      cipher.encrypt(key)
      iv = cipher.random_iv
      ciphertext = cipher.update(plaintext)
      ciphertext << cipher.final
      return ciphertext, iv
    end
    
    def decrypt(family, iv, ciphertext)
      key = find_key(family)
      cipher = get_cipher
      cipher.decrypt(key)
      cipher.iv = iv 
      plaintext = cipher.update(ciphertext)
      plaintext << cipher.final
      return plaintext
    end

    private
    def find_key(family)
      @keystore.get_current_key(family)
    end

    def get_cipher
      OpenSSL::Cipher::Cipher.new('AES-256-CBC')      
    end
    
  end
end
