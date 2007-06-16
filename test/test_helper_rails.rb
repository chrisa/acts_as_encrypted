# setup for testing within rails
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

ActiveRecord::Schema.define(:version => 1) do
  create_table :creditcards do |t|
    t.column :ccnum, :string
    t.column :ccnum_iv, :string
    t.column :ccnum_lastfour, :string
  end
end
