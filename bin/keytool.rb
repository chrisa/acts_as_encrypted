#!/usr/bin/env ruby

require 'rubygems'
require 'openssl'
require 'cmd'
$:.push File.expand_path(File.dirname(__FILE__) + "/../lib")
require 'acts_as_encrypted/keystore'

class Keytool < Cmd
  
  def do_list_families
    if @ks.families.length
      @ks.each_family do |f|
        puts f
      end
    else
      puts "no key families defined"
    end
  end

  def do_create_family(family)
    @ks.create_family(family)
  end
  
  def do_new_key(family)
    @ks.new_key(family, Time.now)
  end

  def do_list_keys(family)
    if @ks.keys(family).length
      @ks.each_key(family) do |k|
        puts k
      end
    else
      puts "no keys for family #{family}"
    end
  end
    
  def do_save
    @ks.save
  end

  def setup
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
      :filename             => keystore
    }
    
    @ks = ActsAsEncrypted::Keystore.new(config)
  end

end

Keytool.run
