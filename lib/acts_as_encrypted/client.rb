require 'drb'
require 'drb/ssl'

module ActsAsEncrypted
  class Client
    
    def initialize
      there = 'drbssl://localhost:3456'
      
      # establish the hostname, use to find generated keys/certs
      full_hostname = `hostname`.strip
      domainname = full_hostname.split('.')[1..-1].join('.')
      hostname = full_hostname.split('.')[0]
      
      cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../../keys")
      config = {
        :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER,
        :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
        :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}/#{hostname}_keypair.pem")),
        :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}/cert_#{hostname}.pem")),
      }

      DRb.start_service nil, nil, config
      @service = DRbObject.new nil, there
    end

    def encrypt(family, plaintext)
      puts "encrypting #{plaintext} with key family #{family}"
      @service.encrypt(family, plaintext)
    end
    
    def decrypt(family, iv, ciphertext)
      plaintext = @service.decrypt(family, iv, ciphertext)
      puts "decrypted: #{plaintext} with key family #{family}"
      plaintext
    end

  end
end
    

