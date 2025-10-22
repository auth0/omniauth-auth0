# frozen_string_literal: true

module OmniAuth
  module Auth0
    # JWTToken class to generate a JWT token for client assertion
    # as per the OAuth 2.0 Client Credentials Grant specification.
    class JWTToken
      attr_reader :client_id, :domain_url, :client_assertion_signing_key, :client_assertion_signing_algorithm

      def initialize(client_id:, domain_url:, client_assertion_signing_key:, client_assertion_signing_algorithm: nil)
        @client_id = client_id
        @domain_url = domain_url
        @client_assertion_signing_key = client_assertion_signing_key
        @client_assertion_signing_algorithm = client_assertion_signing_algorithm || 'RS256'
      end

      def jwt_token
        JWT.encode(jwt_payload, client_assertion_signing_key, client_assertion_signing_algorithm)
      end

      private

      def jwt_payload
        {
          iss: client_id,
          sub: client_id,
          aud: File.join(domain_url, '/'),
          iat: Time.now.utc.to_i,
          exp: Time.now.utc.to_i + 60,
          jti: SecureRandom.uuid
        }
      end
    end
  end
end
