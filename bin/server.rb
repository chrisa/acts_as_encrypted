#!/usr/bin/env ruby

require 'rubygems'
require 'daemons'
require 'drb'
require 'drb/ssl'
require File.expand_path(File.dirname(__FILE__) + "/../lib/acts_as_encrypted/server.rb")

cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../keys")
keystore = File.expand_path(File.dirname(__FILE__) + "/../keys/keystore")

Daemons.run_proc('encryption_server') do
  here = "drbssl://localhost:3456"
  
  # establish the hostname, use to find generated keys/certs
  full_hostname = `hostname`.strip
  domainname = full_hostname.split('.')[1..-1].join('.')
  hostname = full_hostname.split('.')[0]

  config = {
    :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
    :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
    :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
    :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
    :filename             => keystore
  }
  
  DRb.start_service here, ActsAsEncrypted::Server.new(config), config
  DRb.thread.join
end
