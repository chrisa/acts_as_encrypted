require 'openssl'
require 'base64'

module ActsAsEncrypted
  class Engine
    class Local < Engine
      
      def initialize(config)
        # server config -- required to decrypt keystore
        @keystore = ActsAsEncrypted::Keystore.new(config)
      end

      # Validate config: for us, and for the keystore.
      # Throws CryptoConfigError if the configuration is
      # not viable:
      #
      # We expect to get:
      # * :SSLPrivateKey  (OpenSSL::PKey::RSA)
      # * :SSLCertificate (OpenSSL::X509::Certificate)
      # * :filename       (String)
      #
      def self.validate(config)
        if config[:SSLPrivateKey].nil? ||
            config[:SSLPrivateKey].class != OpenSSL::PKey::RSA
          raise CryptoConfigError.new("invalid :SSLPrivateKey")
        end

        if config[:SSLCertificate].nil? ||
            config[:SSLCertificate].class != OpenSSL::X509::Certificate
          raise CryptoConfigError.new("invalid :SSLCertificate")
        end

        if config[:filename].nil?
          raise CryptoConfigError.new("missing :filename")
        end

        if !File.readable?(config[:filename])
          raise CryptoConfigError.new("#{config[:filename]} is unreadable")
        end
      end

      # The encryption method. Encrypts the given plaintext with a key
      # from the given family, either the current key if keyid is nil,
      # or the key specified as keyid. 
      # 
      # Returns the ciphertext and IV as base64 encoded strings, and the
      # key used, whether it was specified or selected as the current
      # key.
      # 
      # Can raise a CryptoFailureError, in case of failed encryption.
      def encrypt(family, keyid, plaintext)
        if keyid
          key = @keystore.get_key(family, keyid)
        else
          key = @keystore.get_live_key(family)
          keyid = key.keyid
        end
        begin
          cipher = get_cipher
          cipher.encrypt(key.key)
          iv = cipher.random_iv
          ciphertext = cipher.update(plaintext)
          ciphertext << cipher.final
        rescue
          raise CryptoFailureError.new
        end
        return Base64.encode64(ciphertext).chomp, Base64.encode64(iv).chomp, keyid
      end
      
      # The decryption method. Decrypts the given ciphertext (as a
      # base64 encoded string) with the specified key family and keyid,
      # using the specified IV (also base64 encoded string).
      #
      # Returns the plaintext, or raises a CryptoFailureError.
      def decrypt(family, keyid, iv, ciphertext)
        if keyid
          key = @keystore.get_key(family, keyid)
        else
          key = @keystore.get_live_key(family)
          keyid = key.keyid
        end
        begin
          cipher = get_cipher
          cipher.decrypt(key.key)
          cipher.iv = Base64.decode64(iv)
          plaintext = cipher.update(Base64.decode64(ciphertext))
          plaintext << cipher.final
        rescue => e
          raise CryptoFailureError.new("#{e.class}: #{e.message}")
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
  end
end
