$:.push File.expand_path(File.dirname(__FILE__) + "/../lib")

require 'test/unit'
['/opt/local', '/usr/local'].each do |path|
  break if load "#{path}/bin/QuickCert"
end

testdir = File.expand_path(File.dirname(__FILE__))

CA = {}
CERTS = []

CA[:hostname] = 'testhost'
CA[:domainname] = 'testdomain'
CA[:CA_dir] = 'CA'
CA[:password] = '1234'

CERTS << {
  :type => 'server',
  :hostname => "testhost-server",
}

CERTS << {
  :type => 'client',
  :user => 'testhost',
  :email => 'aee@nodnol.org'
}

require 'QuickCert/defaults'

Dir.chdir(testdir) do 
  begin
    Dir.mkdir('keys')
    Dir.chdir('keys') do
      puts "creating CA"
      qc = QuickCert.new CA
      
      CERTS.each do |cert_config|
        puts "creating #{cert_config[:type]} cert"
        qc.create_cert cert_config
      end
    end
  rescue
    nil
  end
end

# Define a testing encryption engine which always causes an error.
module ActsAsEncrypted
  class Engine
    class Error < Engine

      def initialize(config)
      end

      def encrypt(family, keyid, plaintext)
        raise CryptoFailureError.new("testing crypto failure (encrypt)")
      end

      def decrypt(family, keyid, iv, ciphertext)
        raise CryptoFailureError.new("testing crypto failure (decrypt)")
      end

    end
  end
end
