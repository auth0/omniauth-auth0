# frozen_string_literal: true

require 'base64'
require 'uri'
require 'omniauth-oauth2'
require 'omniauth/auth0/jwt_validator'
require 'omniauth/auth0/telemetry'

module OmniAuth
  module Strategies
    # Auth0 OmniAuth strategy
    class Auth0 < OmniAuth::Strategies::OAuth2
      include OmniAuth::Auth0::Telemetry

      option :name, 'auth0'
      option :authorize_params_passthru, []

      args %i[
        client_id
        client_secret
        domain
        key_host
      ]

      # Setup client URLs used during authentication
      def client
        options.client_options.site = domain_url
        options.client_options.authorize_url = '/authorize'
        options.client_options.token_url = '/oauth/token'
        options.client_options.userinfo_url = '/userinfo'
        super
      end

      # Use the "sub" key of the userinfo returned
      # as the uid (globally unique string identifier).
      uid { raw_info['sub'] }

      # Build the API credentials hash with returned auth data.
      credentials do
        credentials = {
          'token' => access_token.token,
          'expires' => true
        }

        if access_token.params
          credentials.merge!(
            'id_token' => access_token.params['id_token'],
            'token_type' => access_token.params['token_type'],
            'refresh_token' => access_token.refresh_token
          )
        end

        # Make sure the ID token can be verified and decoded.
        auth0_jwt = OmniAuth::Auth0::JWTValidator.new(options)
        jwt_decoded = auth0_jwt.decode(credentials['id_token'])
        fail!(:invalid_id_token) unless jwt_decoded.length

        credentials
      end

      # Store all raw information for use in the session.
      extra do
        {
          raw_info: raw_info
        }
      end

      # Build a hash of information about the user
      # with keys taken from the Auth Hash Schema.
      info do
        {
          name: raw_info['name'] || raw_info['sub'],
          nickname: raw_info['nickname'],
          email: raw_info['email'],
          image: raw_info['picture']
        }
      end

      # Define the parameters used for the /authorize endpoint
      def authorize_params
        params = super
        parsed_query = Rack::Utils.parse_query(request.query_string)
        passthru = ['connection', 'prompt'] | options.authorize_params_passthru
        params.merge(parsed_query.select{ |key| passthru.include? key })
      end

      def build_access_token
        options.token_params[:headers] = { 'Auth0-Client' => telemetry_encoded }
        super
      end

      # Declarative override for the request phase of authentication
      def request_phase
        if no_client_id?
          # Do we have a client_id for this Application?
          fail!(:missing_client_id)
        elsif no_client_secret?
          # Do we have a client_secret for this Application?
          fail!(:missing_client_secret)
        elsif no_domain?
          # Do we have a domain for this Application?
          fail!(:missing_domain)
        else
          # All checks pass, run the Oauth2 request_phase method.
          super
        end
      end

      private

      # Parse the raw user info.
      def raw_info
        userinfo_url = options.client_options.userinfo_url
        @raw_info ||= access_token.get(userinfo_url).parsed
      end

      # Check if the options include a client_id
      def no_client_id?
        ['', nil].include?(options.client_id)
      end

      # Check if the options include a client_secret
      def no_client_secret?
        ['', nil].include?(options.client_secret)
      end

      # Check if the options include a domain
      def no_domain?
        ['', nil].include?(options.domain)
      end

      # Normalize a domain to a URL.
      def domain_url
        domain_url = URI(options.domain)
        domain_url = URI("https://#{domain_url}") if domain_url.scheme.nil?
        domain_url.to_s
      end
    end
  end
end
