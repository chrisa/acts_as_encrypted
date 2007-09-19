require File.dirname(__FILE__) + '/test_helper'
require 'acts_as_encrypted/engine'

class EngineTest < Test::Unit::TestCase
  
  def setup
    full_hostname = `hostname`.strip
    hostname = full_hostname.split('.')[0]
    cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../keys")
    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :filename             => "#{cryptoroot}/keystore",
      :initializing         => true
    }
    @ks = ActsAsEncrypted::Keystore.new(config)
    @ks.create_family('ccnum')
    f = @ks.family('ccnum')
    @ccnum_id = f.new_key(1)
    @ks.create_family('name')
    f = @ks.family('name')
    @name_id = f.new_key(1)
    @ks.save

    config.delete(:initializing)
    ActsAsEncrypted::Engine.engine = 'local'
    ActsAsEncrypted::Engine.config = config
    ActsAsEncrypted::Engine.reload
  end
  
  def test_engine
    e = ActsAsEncrypted::Engine.engine
    assert e
  end

  def test_encrypt
    e = ActsAsEncrypted::Engine.engine
    ciphertext, iv, keyid = e.encrypt('ccnum', nil, '0000000000000000')
    assert ciphertext
    assert iv
    assert_equal @ccnum_id, keyid
  end

  def test_decrypt
    e = ActsAsEncrypted::Engine.engine
    ciphertext, iv, keyid = e.encrypt('ccnum', nil, '0000000000000000')
    plaintext = e.decrypt('ccnum', keyid, iv, ciphertext)
    assert_equal '0000000000000000', plaintext
  end

  def test_no_iv_decrypt
    e = ActsAsEncrypted::Engine.engine
    begin
      plaintext = e.decrypt('ccnum', @ccnum_id, nil, "GUoLmQdOjmYDk9y7/KTJZ+Z3CpPVuFZCay1OyEZWExE=")
    rescue => e
      assert_equal ActsAsEncrypted::CryptoFailureError, e.class
    else
      assert nil, "no exception raised"
    end
  end

  def test_wrong_iv_decrypt
    e = ActsAsEncrypted::Engine.engine
    begin
      plaintext = e.decrypt('ccnum', @ccnum_id, "lxlsQxW/yU/cKITgoN9EXA==", "GUoLmQdOjmYDk9y7/KTJZ+Z3CpPVuFZCay1OyEZWExE=")
    rescue => e
      assert_equal ActsAsEncrypted::CryptoFailureError, e.class
    else
      assert nil, "no exception raised"
    end
  end

  def test_key_not_found_decrypt
    e = ActsAsEncrypted::Engine.engine
    ciphertext, iv, keyid = e.encrypt('ccnum', nil, '0000000000000000')
    begin
      plaintext = e.decrypt('ccnum', 2, iv, ciphertext)
    rescue => e
      assert_equal ActsAsEncrypted::KeyNotFoundError, e.class
    else
      assert nil, "no exception raised"
    end
  end
  
end
