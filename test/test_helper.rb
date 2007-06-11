require 'test/unit'
load '/usr/local/bin/QuickCert'

CA = {}
CERTS = []

CA[:hostname] = 'testhost'
CA[:domainname] = 'testdomain'
CA[:CA_dir] = File.join Dir.pwd, "CA"
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

Dir.chdir(File.expand_path(File.dirname(__FILE__))) do 
  begin
    Dir.mkdir('keys')
  rescue
    nil
  else
    Dir.chdir('keys') do
      puts "creating CA"
      qc = QuickCert.new CA
      
      CERTS.each do |cert_config|
        puts "creating #{cert_config[:type]} cert"
        qc.create_cert cert_config
      end
    end
  end
end

RAILS_ENV = 'test'
require File.expand_path(File.join(File.dirname(__FILE__), '../../../../config/environment.rb'))

# set up keystore
cryptoroot = File.expand_path(File.dirname(__FILE__) + "/keys")
keystore = "#{cryptoroot}/keystore"

# "server" config, for local engine
config = {
  :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
  :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/testhost-server/testhost-server_keypair.pem")),
  :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/testhost-server/cert_testhost-server.pem")),
  :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
  :filename             => "#{cryptoroot}/keystore",
  :initializing         => true
}
ks = ActsAsEncrypted::Keystore.new(config)
ks.create_family('ccnum')
ks.new_key('ccnum', Time.now)
ks.save

config.delete(:initializing)
ActsAsEncrypted::Engine.engine = 'local'
ActsAsEncrypted::Engine.config = config
