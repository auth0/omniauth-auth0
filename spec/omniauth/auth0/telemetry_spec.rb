require 'spec_helper'
require 'json'

describe OmniAuth::Auth0::Telemetry do

  let(:test_class) { Class.new.extend(OmniAuth::Auth0::Telemetry) }

  describe 'telemetry' do

    it 'should have the correct SDK name' do
      expect(test_class.telemetry).to have_key(:name)
      expect(test_class.telemetry[:name]).to eq('omniauth-auth0')
    end

    it 'should have the correct SDK version' do
      expect(test_class.telemetry).to have_key(:version)
      expect(test_class.telemetry[:version]).to eq(OmniAuth::Auth0::VERSION)
    end

    it 'should include the Ruby version' do
      expect(test_class.telemetry).to have_key(:env)
      expect(test_class.telemetry[:env]).to have_key(:ruby)
      expect(test_class.telemetry[:env][:ruby]).to eq(RUBY_VERSION)
    end

  end

end
