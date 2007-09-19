require 'openssl'

module ActsAsEncrypted

  class KeyNotFoundError < StandardError; end
  class KeyFamilyNotFoundError < StandardError; end
  class InvalidKeyStatusError < StandardError; end

  class Key
    attr_reader :status, :key, :keyid, :start

    ValidStatus = [ 
                   :terminated,
                   :retired,
                   :active,
                   :pending,
                   :expired,
                   :live,
                  ]

    def initialize(start)
      @start = start

      # hex-formatted 4 byte random key keyid.
      @keyid = sprintf('%x', OpenSSL::Random.random_bytes(4).unpack('L').first)

      # all keys start at :active
      @status = :active

      # the key material itself
      @key = OpenSSL::Random.random_bytes(32)
    end
    
    # TODO - enforce state machine
    def status=(status)
      if ValidStatus.include(status)
        @status = status
      else
        raise InvalidKeyStatus.new("invalid key status: #{status.to_s}")
      end
    end
    
    def to_s
      "<id #{keyid} start #{start}>"
    end
  end

  class KeyFamily
    def initialize(name)
      @name = name
      @keys = Hash.new
    end

    # Returns a list of keyids (==date) for each key 
    def key_ids
      @keys.keys
    end

    # Yields each key in the given family.
    def each_key
      @keys.values.each do |k|
        yield k
      end
    end

    # Creates a new key in the given family, with the date specified.
    def new_key(start)
      start = start.to_i
      key = Key.new(start)
      @keys[key.keyid] = key
      key.keyid
    end

    def get_live_key
      # select non-expired keys...
      valid = @keys.values.select do |k|
        k.start <= Time.now.to_i
      end
      
      # sort by start...
      keyid = valid.sort {|a,b| a.start <=> b.start }.last.keyid
        
      # check existence
      unless keyid && @keys[keyid]
        raise KeyNotFoundError.new("no valid key in family #{@name}")
      end

      return @keys[keyid]
    end
    
    def get_key(keyid)
      # check existence
      unless keyid && @keys[keyid]
        raise KeyNotFoundError.new("no key #{keyid} in family #{@name}")
      end

      # check status
      unless @keys[keyid].status == :active
        raise KeyNotFoundError.new("key #{keyid} not in active status")
      end

      return @keys[keyid]      
    end
  end

  class Keystore

    # Loads the keystore, or if the config parameter :initializing is
    # provided, creates and saves a new keystore file.
    def initialize(config)
      @config = config
      if @config[:initializing]
        @config.delete(:initializing)
        init_keystore
      else
        load
      end
    end

    # PUBLIC "get a live key" API

    # Returns the most recent key that isn't dated in the future and
    # is marked :active, for the given key family.
    def get_live_key(family)
      unless @ks[:family]
        raise KeyNotFoundError.new("empty keystore?")
      end
      unless @ks[:family][family.to_s]
        raise KeyNotFoundError.new("no family #{family}")
      end

      f = @ks[:family][family.to_s]
      return f.get_live_key
    end

    # Returns a specific key for the specified family, by date.
    def get_key(family, keyid)
      unless @ks[:family]
        raise KeyNotFoundError.new("empty keystore?")
      end
      unless @ks[:family][family.to_s]
        raise KeyNotFoundError.new("no family #{family}")
      end

      f = @ks[:family][family.to_s]
      return f.get_key(keyid)
    end

    # PUBLIC "key families" API
    
    # Yields the name of each family.
    def each_family
      @ks[:family].each do |k,v|
        yield k
      end
    end

    # Returns a KeyFamily object for the given family.
    def family(f)
      unless @ks[:family][f]
        raise KeyFamilyNotFoundError.new("no key family #{f}")
      end
      return @ks[:family][f]
    end

    # Returns a list of names of known key families.
    def families
      @ks[:family].keys
    end

    # Creates a new empty family of keys.
    def create_family(f)
      @ks[:family][f] = KeyFamily.new(f)
    end

    # FILE HANDLING
    
    # Initialises and saves a new empty keystore. 
    def init_keystore
      @ks = Hash.new
      @ks[:serial] = 0
      @ks[:family] = Hash.new
      save
    end
    
    # Encrypts and saves the current keystore.
    def save
      # get a new KEK
      kek = OpenSSL::Random.random_bytes(32)
      
      # set up a cipher to encrypt the keystore
      cipher = get_cipher
      cipher.encrypt(kek)
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
      encrypted_key = public_rsa.public_encrypt(kek)

      # write out the encrypted KEK, the IV and the ciphertext
      File.open(@config[:filename],  "w") do |fp| 
        fp << encrypted_key
        fp << iv
        fp << ciphertext
      end
    end

    # Loads and decrypts the keystore file specified in the current
    # config hash :filename.
    def load
      # read the keystore file and extract the parts
      file = File.read(@config[:filename])
      encrypted_key = file[0,128]
      iv            = file[128,16]
      ciphertext    = file[144, file.length - 144]
      
      # decrypt the KEK
      kek = @config[:SSLPrivateKey].private_decrypt(encrypted_key)
      
      # decrypt the keystore with the KEK and IV
      cipher = get_cipher
      cipher.decrypt(kek)
      cipher.iv = iv
      ksdata = cipher.update(ciphertext)
      ksdata << cipher.final
       
      # remove the random offset and reanimate the keystore
      offset = ksdata.slice!(0,2).unpack("n").first
      ksdata.slice!(0,offset)
      @ks = Marshal.restore(ksdata)
    end

    private
    # Returns the cipher to be used to encrypt and decrypt the
    # keystore.
    def get_cipher
      OpenSSL::Cipher::Cipher.new('AES-256-CBC')
    end
  end
end
