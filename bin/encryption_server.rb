#!/usr/bin/env ruby
require 'pathname'
require 'rubygems'
require 'daemons'

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

require 'acts_as_encrypted/server.rb'
require 'acts_as_encrypted/options.rb'

# server's options are after the '--', daemons' are before.
server_opts = []
if ARGV.include?('--')
  while ARGV.length > 0
    opt = ARGV.pop
    break if opt == '--'
    server_opts.unshift opt
  end 
end
options = ActsAsEncrypted::Options.parse(server_opts)

full_hostname = `hostname`.strip
hostname = full_hostname.split('.')[0]

config = {
  :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
  :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{options.cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
  :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{options.cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
  :SSLCACertificateFile => "#{options.cryptoroot}/CA/cacert.pem",
  :filename             => options.keystore,
  :server               => options.server
}

Daemons.run_proc('encryption_server') do
  server = ActsAsEncrypted::Server.new(config)
  begin
    server.run
  rescue Interrupt => e
    puts "encryption_server interrupted, shutting down"
  end
end
