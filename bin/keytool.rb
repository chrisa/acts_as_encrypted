#!/usr/bin/env ruby
require 'pathname'
require 'rubygems'
require 'openssl'
require 'cmd'

# allow running standalone or in a rails app
script_dir = Pathname.new(File.dirname(__FILE__)).realpath
rails_script = script_dir + '../vendor/plugins/acts_as_encrypted/bin'
plugin_script = script_dir + '../../../../vendor/plugins/acts_as_encrypted/bin'
if rails_script.directory?
  rails_root = script_dir + '../'
elsif plugin_script.directory?
  rails_root = script_dir + '../../../..'
end
$LOAD_PATH << File.join(rails_root + 'vendor/plugins/acts_as_encrypted/lib')

require 'acts_as_encrypted/keystore'
require 'acts_as_encrypted/options'

class Keytool < Cmd
  
  doc :list_families, "List the key families in the keystore."
  def do_list_families
    if @ks.families.length
      @ks.each_family do |f|
        puts f
      end
    else
      puts "no key families defined"
    end
  end

  doc :create_family, "Create a new family."
  def do_create_family(family)
    @ks.create_family(family)
  end
  
  doc :new_key, "Create a new key in the specified family."
  def do_new_key(family)
    f = @ks.family(family)
    if f
      f.new_key(Time.now)
    else
      puts "family #{family} doesn't exist"
    end
  end

  doc :list_keys, "List the keys in the specified family."
  def do_list_keys(family)
    f = @ks.family(family)
    if f
      if f.key_ids.length > 0
        f.each_key do |k|
          puts k
        end
      else
        puts "no keys for family #{family}"
      end
    else
      puts "family #{family} doesn't exist"
    end
  end
    
  doc :list_all_keys, "List all the keys in the keystore."
  def do_list_all_keys
    if @ks.families.length
      @ks.each_family do |family|
        f = @ks.family(family)
        puts family
        if f.key_ids.length > 0
          f.each_key do |key|
            puts " #{key}"
          end
        else
          puts " no keys for family #{family}"
        end
      end
    else
      puts "no key families defined"
    end

  end

  doc :save, "Write the current state of the keystore to disk."
  def do_save
    @ks.save
  end

  def setup
    # parse, then remove options from ARGV
    options = ActsAsEncrypted::Options.parse(ARGV)
    while ARGV.length > 0
      ARGV.shift
    end
    
    # initializing?
    if options.initializing
      puts "Initializing new keystore"
    end
    
    # establish the hostname, use to find generated keys/certs
    full_hostname = `hostname`.strip
    domainname = full_hostname.split('.')[1..-1].join('.')
    hostname = full_hostname.split('.')[0]
    
    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{options.cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{options.cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
      :SSLCACertificateFile => "#{options.cryptoroot}/CA/cacert.pem",
      :filename             => options.keystore,
      :initializing         => options.initializing
    }
    
    @ks = ActsAsEncrypted::Keystore.new(config)
  end

end

Keytool.run
