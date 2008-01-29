require 'drb'
require 'drb/ssl'

module ActsAsEncrypted
  class Engine
    class Remote < Engine
      
      def initialize(config)
        there = "drbssl://#{config[:server]}"
        DRb.start_service nil, nil, config
        @service = DRbObject.new nil, there
      end
      
      # Validate config: for us, and for the keystore.
      # Throws CryptoConfigError if the configuration is
      # not viable:
      #
      # We expect to get:
      # * :SSLPrivateKey        (OpenSSL::PKey::RSA)
      # * :SSLCertificate       (OpenSSL::X509::Certificate)
      # * :SSLCACertificateFile (String)
      # * :server               (String, hostname:port)
      #
      # Optional:
      # * :SSLVerifyMode        (OpenSSL::SSL::*)
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

        if config[:SSLCACertificateFile].nil?
          raise CryptoConfigError.new("missing :SSLCACertificateFile")
        end

        if !File.readable?(config[:SSLCACertificateFile])
          raise CryptoConfigError.new("#{config[:SSLCACertificateFile]} is unreadable")
        end
        
        if config[:server].nil?
          raise CryptoConfigError.new("missing :server")
        end

        unless config[:server].match(/\w+:\d+/)
          raise CryptoConfigError.new("invalid :server")
        end
      end

      def encrypt(family, keyid, plaintext)
        @service.encrypt(family, keyid, plaintext)
      end
      
      def decrypt(family, keyid, iv, ciphertext)
        @service.decrypt(family, keyid, iv, ciphertext)
      end
      
    end
  end      
end
