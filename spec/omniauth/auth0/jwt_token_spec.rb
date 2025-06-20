# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'jwt'

describe OmniAuth::Auth0::JWTToken do
  let(:client_id) { 'CLIENT_ID' }
  let(:domain_url) { 'https://samples.auth0.com' }
  let(:client_assertion_signing_key) { OpenSSL::PKey::RSA.generate(2048) }

  describe '#jwt_token' do
    it 'generates a valid JWT token' do
      uuid = '12345678-1234-5678-1234-567812345678'
      allow(SecureRandom).to receive(:uuid).and_return(uuid)

      jwt_token = described_class.new(client_id:,
                                      domain_url:,
                                      client_assertion_signing_key:,
                                      client_assertion_signing_algorithm: 'RS256')
                                 .jwt_token
      decoded_token = JWT.decode(jwt_token, client_assertion_signing_key, true, { algorithm: 'RS256' })

      expect(decoded_token[0]['iss']).to eq(client_id)
      expect(decoded_token[0]['sub']).to eq(client_id)
      expect(decoded_token[0]['aud']).to eq("#{domain_url}/")
      expect(decoded_token[0]['iat']).to be_within(5).of(Time.now.utc.to_i)
      expect(decoded_token[0]['exp']).to eq(decoded_token[0]['iat'] + 60)
      expect(decoded_token[0]['jti']).to eq(uuid)
    end

    it 'defaults to RS256 algorithm if not specified' do
      uuid = '12345678-1234-5678-1234-567812345678'
      allow(SecureRandom).to receive(:uuid).and_return(uuid)

      jwt_token = described_class.new(client_id:, domain_url:, client_assertion_signing_key:).jwt_token
      decoded_token = JWT.decode(jwt_token, client_assertion_signing_key, true, { algorithm: 'RS256' })

      expect(decoded_token[0]['iss']).to eq(client_id)
      expect(decoded_token[0]['sub']).to eq(client_id)
      expect(decoded_token[0]['aud']).to eq("#{domain_url}/")
      expect(decoded_token[0]['iat']).to be_within(5).of(Time.now.utc.to_i)
      expect(decoded_token[0]['exp']).to eq(decoded_token[0]['iat'] + 60)
      expect(decoded_token[0]['jti']).to eq(uuid)
    end
  end
end
