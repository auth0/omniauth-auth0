$LOAD_PATH.unshift File.expand_path(__dir__)
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'multi_json'
require 'simplecov'
SimpleCov.start

if ENV['CI'] == 'true'
  require 'simplecov-cobertura'
  SimpleCov.formatter = SimpleCov::Formatter::CoberturaFormatter
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
  config.filter_run focus: true
  config.run_all_when_everything_filtered = true

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
        set :session_secret, '9771aff2c634257053c62ba072c54754bd2cc92739b37e81c3eda505da48c2ec'
        set :session_store, Rack::Session::Cookie
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
