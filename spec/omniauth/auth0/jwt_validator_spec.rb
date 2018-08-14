require 'spec_helper'
require 'json'
require 'jwt'

describe OmniAuth::Auth0::JWTValidator do
  let(:client_id) { 'CLIENT_ID' }
  let(:client_secret) { 'CLIENT_SECRET' }
  let(:domain) { 'samples.auth0.com' }
  let(:future_timecode) { 32503680000 }
  let(:past_timecode) { 303912000 }
  let(:jwks_kid) { 'NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg' }

  let(:jwt_validator) do
    make_jwt_verifier
  end

  let(:rsa_private_key) do
    OpenSSL::PKey::RSA.generate 2048
  end

  let(:rsa_token_jwks) do

    cert = OpenSSL::X509::Certificate.new
    cert.issuer = OpenSSL::X509::Name.parse("/C=BE/O=Auth0/OU=Auth0/CN=Auth0")
    cert.subject = cert.issuer
    cert.not_before = Time.now
    cert.not_after = Time.now + 365 * 24 * 60 * 60
    cert.public_key = rsa_private_key.public_key
    cert.serial = 0x0
    cert.version = 2

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.extensions = [
      ef.create_extension("basicConstraints","CA:TRUE", true),
      ef.create_extension("subjectKeyIdentifier", "hash")
    ]
    cert.add_extension ef.create_extension(
      "authorityKeyIdentifier",
      "keyid:always,issuer:always"
    )

    cert.sign rsa_private_key, OpenSSL::Digest::SHA1.new

    jwks = {
      keys: [
        {
          kid: jwks_kid,
          x5c: [ Base64.encode64(cert.to_der) ]
        }
      ]
    }
    jwks.to_json
  end

  let(:jwks) do
    current_dir = File.dirname(__FILE__)
    jwks_file = File.read("#{current_dir}/../../resources/jwks.json")
    JSON.parse(jwks_file)
  end

  def make_jwt_verifier(opt_domain = domain)
    options = Struct.new(:domain, :client_id, :client_secret)
    OmniAuth::Auth0::JWTValidator.new(options.new(
      opt_domain,
      client_id,
      client_secret
    ))
  end

  def make_hs256_token(payload = nil)
    payload = { sub: 'abc123' } if payload.nil?
    JWT.encode payload, client_secret, 'HS256'
  end

  def make_rs256_token(payload = nil)
    payload = { sub: 'abc123' } if payload.nil?
    JWT.encode payload, rsa_private_key, 'RS256', { kid: jwks_kid }
  end

  def stub_jwks
    stub_request(:get, 'https://samples.auth0.com/.well-known/jwks.json')
      .to_return(
        headers: { 'Content-Type' => 'application/json' },
        body: jwks.to_json,
        status: 200
      )
  end

  def stub_bad_jwks
    stub_request(:get, 'https://samples.auth0.com/.well-known/jwks-bad.json')
      .to_return(
        status: 404
      )
  end

  def stub_dummy_jwks
    stub_request(:get, 'https://example.org/.well-known/jwks.json')
      .to_return(
        headers: { 'Content-Type' => 'application/json' },
        body: rsa_token_jwks,
        status: 200
      )
  end

  describe 'JWT verifier default values' do
    it 'should have the correct issuer' do
      expect(jwt_validator.issuer).to eq('https://samples.auth0.com/')
    end

    it 'should have a nil jwks' do
      expect(jwt_validator.jwks).to eq(nil)
    end
  end

  describe 'JWT verifier token_head' do
    it 'should parse the head of a valid JWT' do
      expect(jwt_validator.token_head(make_hs256_token)['alg']).to eq('HS256')
    end

    it 'should fail parsing the head of a blank JWT' do
      expect(jwt_validator.token_head('')).to eq({})
    end

    it 'should fail parsing the head of an invalid JWT' do
      expect(jwt_validator.token_head('.')).to eq({})
    end

    it 'should throw an exception for invalid JSON' do
      expect(jwt_validator.token_head('QXV0aDA=')).to eq({})
    end
  end

  describe 'JWT verifier jwks_public_cert' do
    it 'should return a public_key' do
      x5c = jwks['keys'].first['x5c'].first
      public_cert = jwt_validator.jwks_public_cert(x5c)
      expect(public_cert.instance_of?(OpenSSL::PKey::RSA)).to eq(true)
    end

    it 'should fail with an invalid x5c' do
      expect do
        jwt_validator.jwks_public_cert('QXV0aDA=')
      end.to raise_error(OpenSSL::X509::CertificateError)
    end
  end

  describe 'JWT verifier jwks_key' do
    before do
      stub_jwks
    end

    it 'should return a key' do
      expect(jwt_validator.jwks_key('alg', jwks_kid)).to eq('RS256')
    end

    it 'should return an x5c key' do
      expect(jwt_validator.jwks_key('x5c', jwks_kid).length).to eq(1)
    end

    it 'should return nil if there is not key' do
      expect(jwt_validator.jwks_key('auth0', jwks_kid)).to eq(nil)
    end

    it 'should return nil if the key ID is invalid' do
      expect(jwt_validator.jwks_key('alg', "#{jwks_kid}_invalid")).to eq(nil)
    end
  end

  describe 'JWT verifier fetch_jwks' do
    before do
      stub_jwks
      stub_bad_jwks
    end

    it 'should return a hash with keys using a valid JWKS URL' do
      expect(jwt_validator.fetch_jwks.has_key?('keys')).to eq(true)
    end

    it 'should return a hash without keys using an invalid JWKS URL' do
      expect(jwt_validator.fetch_jwks('.well-known/jwks-bad.json')
               .has_key?('key')).to eq(false)
    end
  end

  describe 'JWT verifier decode' do
    before do
      stub_jwks
      stub_dummy_jwks
    end

    it 'should fail with passed expiration' do
      payload = {
        exp: past_timecode
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.decode(token)
      end.to raise_error(JWT::ExpiredSignature)
    end

    it 'should fail with missing issuer' do
      expect do
        jwt_validator.decode(make_hs256_token)
      end.to raise_error(JWT::InvalidIssuerError)
    end

    it 'should fail with invalid issuer' do
      payload = {
        iss: "https://auth0.com/"
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.decode(token)
      end.to raise_error(JWT::InvalidIssuerError)
    end

    it 'should fail with a future not before' do
      payload = {
        nbf: future_timecode,
        iss: "https://#{domain}/"
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.decode(token)
      end.to raise_error(JWT::ImmatureSignature)
    end

    it 'should fail with missing audience' do
      payload = {
        iss: "https://#{domain}/"
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.decode(token)
      end.to raise_error(JWT::InvalidAudError)
    end

    it 'should fail with invalid audience' do
      payload = {
        iss: "https://#{domain}/",
        aud: "Auth0"
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.decode(token)
      end.to raise_error(JWT::InvalidAudError)
    end

    it 'should decode a valid HS256 token with multiple audiences' do
      payload = {
        iss: "https://#{domain}/",
        aud: [
          client_id,
          "https://#{domain}/userinfo"
        ]
      }
      token = make_hs256_token(payload)
      expect(jwt_validator.decode(token).length).to eq(2)
    end

    it 'should decode a standard HS256 token' do
      sub = 'abc123'
      payload = {
        sub: sub,
        exp: future_timecode,
        iss: "https://#{domain}/",
        iat: past_timecode,
        aud: client_id
      }
      token = make_hs256_token(payload)
      decoded_token = jwt_validator.decode(token)
      expect(decoded_token.first['sub']).to eq(sub)
    end

    it 'should decode a standard RS256 token' do
      domain = 'example.org'
      sub = 'abc123'
      payload = {
        sub: sub,
        exp: future_timecode,
        iss: "https://#{domain}/",
        iat: past_timecode,
        aud: client_id,
        kid: jwks_kid
      }
      token = make_rs256_token(payload)
      jwt_validator = make_jwt_verifier(domain)
      decoded_token = jwt_validator.decode(token)
      expect(decoded_token.first['sub']).to eq(sub)
    end
  end
end