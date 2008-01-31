# setup for testing within rails
RAILS_ENV = 'test'
require File.expand_path(File.join(File.dirname(__FILE__), '../../../../config/environment.rb'))

ActiveRecord::Schema.define(:version => 1) do
  create_table :creditcards do |t|
    t.column :cardholder, :string
    t.column :cardholder_iv, :string
    t.column :cardholder_initial, :string
    t.column :ccnum, :string
    t.column :ccnum_iv, :string
    t.column :ccnum_lastfour, :string

    t.column :ccnum_keyid, :string
    t.column :name_keyid, :string
    
    t.column :cardtype, :string
  end
end

class Creditcard < ActiveRecord::Base
  acts_as_encrypted :ccnum
  encrypts :ccnum, :lastfour => lambda { |cc| cc[-4,4] }
  encrypts :cardholder, :family => :name, 
                        :initial => lambda { |n| n[0,1] }
  validates_presence_of :cardtype
end

# For looking directly at the creditcards table in tests
class RawCreditcard < ActiveRecord::Base
  set_table_name :creditcards
end

# For testing incorrectly-used acts_as_encrypted macro
# no key family at all:
class NoKeyFamily < ActiveRecord::Base
  set_table_name :creditcards
  acts_as_encrypted
end
# default key family only:
class DefaultKeyFamily < ActiveRecord::Base
  set_table_name :creditcards
  acts_as_encrypted :ccnum
  encrypts :ccnum
end
