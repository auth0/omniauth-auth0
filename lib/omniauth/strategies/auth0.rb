# frozen_string_literal: true

require 'base64'
require 'uri'
require 'securerandom'
require 'omniauth-oauth2'
require 'omniauth/auth0/jwt_token'
require 'omniauth/auth0/jwt_validator'
require 'omniauth/auth0/telemetry'
require 'omniauth/auth0/errors'

module OmniAuth
  module Strategies
    # Auth0 OmniAuth strategy
    class Auth0 < OmniAuth::Strategies::OAuth2
      include OmniAuth::Auth0::Telemetry
      AUTHORIZATION_CODE_GRANT_TYPE = 'authorization_code'
      CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

      option :name, 'auth0'

      args %i[
        client_id
        client_secret
        domain
      ]

      # Setup client URLs used during authentication
      def client
        options.client_options.site = domain_url
        options.client_options.authorize_url = '/authorize'
        options.client_options.token_url = '/oauth/token'
        options.client_options.userinfo_url = '/userinfo'
        setup_client_options_auth_scheme

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

        # Retrieve and remove authorization params from the session
        session_authorize_params = session['authorize_params'] || {}
        session.delete('authorize_params')

        auth_scope = session_authorize_params[:scope]
        if auth_scope.respond_to?(:include?) && auth_scope.include?('openid')
          # Make sure the ID token can be verified and decoded.
          jwt_validator.verify(credentials['id_token'], session_authorize_params)
        end

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
        %w[connection connection_scope prompt screen_hint login_hint organization invitation ui_locales].each do |key|
          params[key] = request.params[key] if request.params.key?(key)
        end

        # Generate nonce
        params[:nonce] = SecureRandom.hex
        # Generate leeway if none exists
        params[:leeway] = 60 unless params[:leeway]

        # Store authorize params in the session for token verification
        session['authorize_params'] = params.to_hash

        params
      end

      def build_access_token
        options.token_params.merge!(client_assertion_signing_key_token_params) if client_assertion_signing_key_auth?
        options.token_params[:headers] = { 'Auth0-Client' => telemetry_encoded }
        super
      end

      # Declarative override for the request phase of authentication
      def request_phase
        return fail!(:missing_client_id) if no_client_id?
        return fail!(:missing_client_secret) if no_client_secret?
        return fail!(:missing_domain) if no_domain?
        return fail!(:missing_client_assertion_signing_key) if no_client_assertion_signing_key?

        # All checks pass, run the Oauth2 request_phase method.
        super
      end

      def callback_phase
        super
      rescue OmniAuth::Auth0::TokenValidationError => e
        fail!(:token_validation_error, e)
      end

      private

      def client_assertion_signing_key_auth?
        options['client_assertion_signing_key']
      end

      def client_assertion_signing_key_token_params
        {
          grant_type: AUTHORIZATION_CODE_GRANT_TYPE,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: jwt_token,
          audience: domain_url
        }
      end

      def jwt_validator
        @jwt_validator ||= OmniAuth::Auth0::JWTValidator.new(options)
      end

      def jwt_token
        OmniAuth::Auth0::JWTToken.new(client_id: options.client_id,
                                      domain_url:,
                                      client_assertion_signing_key: options.client_assertion_signing_key,
                                      client_assertion_signing_algorithm: options.client_assertion_signing_algorithm)
                                 .jwt_token
      end

      # Parse the raw user info.
      def raw_info
        return @raw_info if @raw_info

        if access_token["id_token"]
          claims, header = jwt_validator.decode(access_token["id_token"])
          @raw_info = claims
        else
          userinfo_url = options.client_options.userinfo_url
          @raw_info = access_token.get(userinfo_url).parsed
        end

        return @raw_info
      end

      # Check if the options include a client_id
      def no_client_id?
        ['', nil].include?(options.client_id)
      end

      # Check if the options include a client_secret
      def no_client_secret?
        ['', nil].include?(options.client_secret) && !options.key?('client_assertion_signing_key')
      end

      # Check if the options include a domain
      def no_domain?
        ['', nil].include?(options.domain)
      end

      # Check if the options include a client_assertion_signing_key
      def no_client_assertion_signing_key?
        options.key?('client_assertion_signing_key') && ['', nil].include?(options.client_assertion_signing_key)
      end

      # Normalize a domain to a URL.
      def domain_url
        domain_url = URI(options.domain)
        domain_url = URI("https://#{domain_url}") if domain_url.scheme.nil?
        domain_url.to_s
      end

      # Setup the auth_scheme for the client options if using client assertion signing key
      def setup_client_options_auth_scheme
        return unless client_assertion_signing_key_auth?

        options.client_options.auth_scheme = :private_key_jwt
      end
    end
  end
end
