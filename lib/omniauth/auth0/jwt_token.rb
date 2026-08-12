# frozen_string_literal: true

require 'jwt'
require 'securerandom'

module OmniAuth
  module Auth0
    # JWTToken class to generate a JWT token for client assertion
    # as per the OAuth 2.0 Client Credentials Grant specification.
    class JWTToken
      attr_reader :client_id, :domain_url, :client_assertion_signing_key, :client_assertion_signing_algorithm,
                  :client_assertion_signing_key_id

      # Create a new client assertion JWT generator.
      # @param client_id string - Application Client ID.
      # @param domain_url string - Application domain, used to build the audience.
      # @param client_assertion_signing_key key - Private key used to sign the assertion.
      # @param client_assertion_signing_algorithm string - Signing algorithm, defaults to RS256.
      # @param client_assertion_signing_key_id string - Key ID of the signing key (optional). When
      #   given, it is sent as the "kid" header so Auth0 can pick the matching public key.
      def initialize(client_id, domain_url, client_assertion_signing_key, client_assertion_signing_algorithm = nil,
                     client_assertion_signing_key_id: nil)
        @client_id = client_id
        @domain_url = domain_url
        @client_assertion_signing_key = client_assertion_signing_key
        @client_assertion_signing_algorithm = client_assertion_signing_algorithm || 'RS256'
        @client_assertion_signing_key_id = client_assertion_signing_key_id
      end

      def jwt_token
        JWT.encode(jwt_payload, client_assertion_signing_key, client_assertion_signing_algorithm, jwt_headers)
      end

      private

      # Build the additional JWT header parameters. The "kid" (key ID) header is only included when a
      # key ID is configured, so that Auth0 can select the matching public key during key rotation.
      # @return hash - The extra headers to merge into the JWT header, empty hash if none.
      def jwt_headers
        return {} if ['', nil].include?(client_assertion_signing_key_id)

        { kid: client_assertion_signing_key_id }
      end

      def jwt_payload
        {
          iss: client_id,
          sub: client_id,
          aud: File.join(domain_url, '/oauth/token'),
          iat: Time.now.utc.to_i,
          exp: Time.now.utc.to_i + 60,
          jti: SecureRandom.uuid
        }
      end
    end
  end
end
