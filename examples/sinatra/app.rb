require 'sinatra'
require 'omniauth-auth0'
require 'dotenv/load'

use OmniAuth::Builder do
  provider :auth0, ENV['CLIENT_ID'], ENV['CLIENT_SECRET'], ENV['DOMAIN']
end

enable :sessions
set :session_secret, ENV['SESSION_SECRET']

get '/' do
  'Auth0 OmniAuth Example for Sinatra'
end
