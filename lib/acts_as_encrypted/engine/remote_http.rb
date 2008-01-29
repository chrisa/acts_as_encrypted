require 'json'
require 'net/http'
require 'uri'

module ActsAsEncrypted
  class Engine
    class RemoteHttp < Engine

      def initialize(config)
        @config = config
      end
      
      # Validate config. We expect:
      # * :server_uri (string, URI)
      #
      def self.validate(config)
        if config[:server_uri].nil?
          raise CryptoConfigError.new("missing :server_uri")
        end

        begin 
          URI.parse(config[:server_uri])
        rescue URI::InvalidURIError
          raise CryptoConfigError.new("invalid :server_uri")
        end
      end

      def encrypt(family, keyid, plaintext)
        content = { 'family' => family, 'keyid' => keyid, 'plaintext' => plaintext }
        res = request(:encrypt, content)
        return res['ciphertext'], res['iv'], res['keyid']
      end
      
      def decrypt(family, keyid, iv, ciphertext)
        content = { 'family' => family, 'keyid' => keyid, 'ciphertext' => ciphertext, 'iv' => iv }
        res = request(:decrypt, content)
        res['plaintext']
      end
      
      private

      def request(op, content)
        url = URI.parse(sprintf("%s/%s", @config[:server_uri], op.to_s))
        req = Net::HTTP::Post.new(url.path)
        req.set_content_type('text/json')
        req.body = JSON.fast_generate(content)

        begin
          res = Net::HTTP.new(url.host, url.port).start {|http| http.request(req) }
          case res
          when Net::HTTPSuccess
            json = res.body
            JSON.parse(json)
          else
            res.error!
          end
        rescue EOFError => e
          raise CryptoFailureError.new(e.message)
        end
      end

    end
  end
end  
      
