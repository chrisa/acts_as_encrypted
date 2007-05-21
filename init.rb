# Include hook code here
require 'acts_as_encrypted'
ActiveRecord::Base.class_eval do
  include ActsAsEncrypted
end
