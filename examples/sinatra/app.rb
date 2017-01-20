require 'sinatra'
require 'omniauth-auth0'
require 'dotenv/load'

use Rack::Session::Cookie
use OmniAuth::Builder do
  provider :auth0, ENV['CLIENT_ID'], ENV['CLIENT_SECRET']
end

set :session_secret, ENV['SESSION_SECRET']

get '/' do
  'Auth0 OmniAuth Example for Sinatra'
end
