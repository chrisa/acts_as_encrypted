#!/usr/bin/env ruby

require 'rubygems'
require 'daemons'
require 'drb'
require 'drb/ssl'

$:.push File.expand_path(File.dirname(__FILE__) + "/../lib")
require 'acts_as_encrypted/server.rb'

here = "drbssl://localhost:3456"
cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../keys")

full_hostname = `hostname`.strip
hostname = full_hostname.split('.')[0]

config = {
  :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
  :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
  :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
  :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
  :filename             => "#{cryptoroot}/keystore",
}

Daemons.run_proc('encryption_server') do
  server = ActsAsEncrypted::Server.new(config)
  DRb.start_service here, server.api, config
  DRb.thread.join
end
