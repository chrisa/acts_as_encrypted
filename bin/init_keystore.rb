#!/usr/bin/env ruby

require 'rubygems'
require 'openssl'
$:.push File.expand_path(File.dirname(__FILE__) + "/../lib")
require 'acts_as_encrypted/keystore'

cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../keys")
keystore = File.expand_path(File.dirname(__FILE__) + "/../keys/keystore")

# establish the hostname, use to find generated keys/certs
full_hostname = `hostname`.strip
domainname = full_hostname.split('.')[1..-1].join('.')
hostname = full_hostname.split('.')[0]

config = {
  :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
  :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
  :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
  :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
  :initializing         => true,
  :filename             => keystore
}
  
ActsAsEncrypted::Keystore.new(config)
