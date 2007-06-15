require File.dirname(__FILE__) + '/test_helper'
require 'acts_as_encrypted/keystore'

class KeyStoreTest < Test::Unit::TestCase

  def test_init_keystore 
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
  end

  def test_init_save_and_reload
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
    ks.save
    
    config.delete(:initializing)
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
  end

  def test_many_keys_then_save_and_reload
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
    ks.create_family('foo')

    (1..1000).each do 
      ks.new_key('foo', Time.now)
    end
    
    ks.save

    config.delete(:initializing)
    ks = ActsAsEncrypted::Keystore.new(config)
    assert_equal 1, ks.families.length
    assert_equal 1000, ks.keys('foo').length
  end

  def test_new_family
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
    
    f = ks.families
    assert_equal 0, f.length

    ks.create_family('foo')
    f = ks.families
    assert_equal 1, f.length
    assert_equal 'foo', f.first
  end

  def test_new_key
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
    ks.create_family('foo')
    ks.new_key('foo', Time.now)
  end

  private 
  def get_config
    cryptoroot = File.expand_path(File.join(File.dirname(__FILE__),'keys'))
    {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/testhost-server/testhost-server_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/testhost-server/cert_testhost-server.pem")),
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :filename             => "#{cryptoroot}/keystore"
    }
  end
end

