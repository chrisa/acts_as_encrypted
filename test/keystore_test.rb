require File.dirname(__FILE__) + '/test_helper'
require 'acts_as_encrypted/keystore'

class KeyStoreTest < Test::Unit::TestCase

  def setup
    config = get_config
    config[:initializing] = true
    @ks = ActsAsEncrypted::Keystore.new(config)
  end

  def test_init_keystore 
    assert @ks
  end

  def test_init_save_and_reload
    @ks.save
    
    config = get_config
    config.delete(:initializing)
    reloaded_ks = ActsAsEncrypted::Keystore.new(config)
    assert reloaded_ks
  end

  def test_many_keys_then_save_and_reload
    @ks.create_family('foo')

    (1..100).each do |i|
      @ks.new_key('foo', Time.now.to_i + i)
    end
    
    @ks.save

    config = get_config
    config.delete(:initializing)
    reloaded_ks = ActsAsEncrypted::Keystore.new(config)
    assert_equal 1, reloaded_ks.families.length
    assert_equal 100, reloaded_ks.keys('foo').length
  end

  def test_new_family
    f = @ks.families
    assert_equal 0, f.length

    @ks.create_family('foo')
    f = @ks.families
    assert_equal 1, f.length
    assert_equal 'foo', f.first
  end

  def test_new_key
    @ks.create_family('foo')
    t = Time.now.to_i
    @ks.new_key('foo', t)
    assert @ks.get_key('foo', t)
  end

  def test_family_not_found
    begin
      @ks.get_key('foofamily', 0)
    rescue => e
      assert_equal ActsAsEncrypted::KeyNotFoundError, e.class
    else
      assert nil, "no exception raised"
    end
  end

  def test_key_not_found
    @ks.create_family('foo')
    begin
      @ks.get_key('foo', 0)
    rescue => e
      assert_equal ActsAsEncrypted::KeyNotFoundError, e.class
    else
      assert nil, "no exception raised"
    end
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

