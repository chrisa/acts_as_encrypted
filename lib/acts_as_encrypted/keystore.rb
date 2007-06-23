require 'openssl'

module ActsAsEncrypted

  class KeyNotFoundError < StandardError; end

  class Keystore

    def initialize(config)
      @config = config
      if @config[:initializing]
        @config.delete(:initializing)
        init_keystore
      else
        load
      end
    end

    def get_current_key(family)
      unless @ks[:family]
        raise KeyNotFoundError.new("empty keystore?")
      end
      unless @ks[:family][family.to_s]
        raise KeyNotFoundError.new("no family #{family}")
      end
      valid = @ks[:family][family.to_s].keys.select do |t|
        t <= Time.now.to_i
      end
      start = valid.sort.last
      unless start && @ks[:family][family.to_s][start]
        raise KeyNotFoundError.new("no valid key in family #{family}")
      end

      return @ks[:family][family.to_s][start], start
    end

    def get_key(family, start)
      unless @ks[:family]
        raise KeyNotFoundError.new("empty keystore?")
      end
      unless @ks[:family][family.to_s]
        raise KeyNotFoundError.new("no family #{family}")
      end
      unless @ks[:family][family.to_s][start]
        raise KeyNotFoundError.new("no key #{start} in family #{family}")
      end

      return @ks[:family][family.to_s][start]
    end

    def each_family
      @ks[:family].each do |k,v|
        yield k
      end
    end

    def families
      @ks[:family].keys
    end

    def keys(family)
      @ks[:family][family].keys
    end

    def each_key(family)
      @ks[:family][family].keys.each do |k|
        yield k
      end
    end

    def new_key(f, start)
      start = start.to_i
      k = OpenSSL::Random.random_bytes(32)
      @ks[:family][f][start] = k
    end

    def create_family(f)
      @ks[:family][f] = Hash.new
    end

    def init_keystore
      @ks = Hash.new
      @ks[:serial] = 0
      @ks[:family] = Hash.new
      @kek = OpenSSL::Random.random_bytes(32)
      save
    end

    def save
      # set up a cipher to encrypt the keystore
      cipher = get_cipher
      cipher.encrypt(@kek)
      iv = cipher.random_iv

      # dump the keystore and pad it with a random length
      ksdata = OpenSSL::Random.random_bytes(2)
      len = ksdata.unpack("n").first
      ksdata << OpenSSL::Random.random_bytes(len)
      ksdata << Marshal.dump(@ks)

      # encrypt the keystore with its KEK
      ciphertext = cipher.update(ksdata)
      ciphertext << cipher.final

      # encrypt the KEK
      public_rsa = @config[:SSLPrivateKey].public_key
      encrypted_key = public_rsa.public_encrypt(@kek)

      # write out the encrypted KEK, the IV and the ciphertext
      File.open(@config[:filename],  "w") do |fp| 
        fp << encrypted_key
        fp << iv
        fp << ciphertext
      end
    end

    def load
      # read the keystore file and extract the parts
      file = File.read(@config[:filename])
      encrypted_key = file[0,128]
      iv            = file[128,16]
      ciphertext    = file[144, file.length - 144]
      
      # decrypt the KEK
      @kek = @config[:SSLPrivateKey].private_decrypt(encrypted_key)
      
      # decrypt the keystore with the KEK and IV
      cipher = get_cipher
      cipher.decrypt(@kek)
      cipher.iv = iv
      ksdata = cipher.update(ciphertext)
      ksdata << cipher.final
       
      # remove the random offset and reanimate the keystore
      offset = ksdata.slice!(0,2).unpack("n").first
      ksdata.slice!(0,offset)
      @ks = Marshal.restore(ksdata)
    end

    private
    def get_cipher
      OpenSSL::Cipher::Cipher.new('AES-256-CBC')
    end
  end
end
