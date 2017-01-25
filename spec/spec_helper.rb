$LOAD_PATH.unshift File.expand_path('..', __FILE__)
$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)

require 'simplecov'
if ENV['COVERAGE']
  SimpleCov.start do
    minimum_coverage(89.8)
  end
end
require 'rspec'
require 'rack/test'
require 'webmock/rspec'
require 'omniauth'
require 'omniauth-auth0'
require 'sinatra'

WebMock.disable_net_connect!

RSpec.configure do |config|
  config.include WebMock::API
  config.include Rack::Test::Methods
  config.extend OmniAuth::Test::StrategyMacros, type: :strategy

  def app
    @app || make_application
  end

  def make_application(options = {})
    client_id = 'CLIENT_ID'
    secret = 'CLIENT_SECRET'
    domain = 'samples.auth0.com'
    client_id = options.delete(:client_id) if options.key?(:client_id)
    secret = options.delete(:client_secret) if options.key?(:client_secret)
    domain = options.delete(:domain) if options.key?(:domain)

    Sinatra.new do
      configure do
        enable :sessions
        set :show_exceptions, false
        set :session_secret, 'TEST'
      end

      use OmniAuth::Builder do
        provider :auth0, client_id, secret, domain, options
      end

      get '/auth/auth0/callback' do
        MultiJson.encode(env['omniauth.auth'])
      end
    end
  end
end

OmniAuth.config.logger = Logger.new('/dev/null')
