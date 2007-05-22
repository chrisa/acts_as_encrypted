#!/opt/csw/bin/ruby

require 'rubygems'
require 'daemons'
require 'drb'
require 'drb/ssl'
require File.expand_path(File.dirname(__FILE__) + "/../lib/acts_as_encrypted/server.rb")

Daemons.run_proc('encryption_server') do
  here = "drbssl://localhost:3456"
  
  cryptoroot = "/home/chris/cryptodb/DBEncrypt/crypto"
  config = {
    :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
    :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/localhost/localhost_keypair.pem")),
    :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/localhost/cert_localhost.pem")),
    :SSLCACertificateFile => "CA/cacert.pem",
  }
  
  DRb.start_service here, ActsAsEncrypted::Server.new, config
  DRb.thread.join
end
