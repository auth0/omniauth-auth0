require 'spec_helper'
require 'json'
require 'jwt'

describe OmniAuth::Auth0::JWTValidator do
  #
  # Reused data
  #

  let(:client_id) { 'CLIENT_ID' }
  let(:client_secret) { 'CLIENT_SECRET' }
  let(:domain) { 'samples.auth0.com' }
  let(:future_timecode) { 32_503_680_000 }
  let(:past_timecode) { 303_912_000 }
  let(:jwks_kid) { 'NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg' }

  let(:rsa_private_key) do
    OpenSSL::PKey::RSA.generate 2048
  end

  let(:rsa_token_jwks) do
    {
      keys: [
        {
          kid: jwks_kid,
          x5c: [Base64.encode64(make_cert(rsa_private_key).to_der)]
        }
      ]
    }.to_json
  end

  let(:jwks) do
    current_dir = File.dirname(__FILE__)
    jwks_file = File.read("#{current_dir}/../../resources/jwks.json")
    JSON.parse(jwks_file, symbolize_names: true)
  end

  #
  # Specs
  #

  describe 'JWT verifier default values' do
    let(:jwt_validator) do
      make_jwt_validator
    end

    it 'should have the correct issuer' do
      expect(jwt_validator.issuer).to eq('https://samples.auth0.com/')
    end
  end

  describe 'JWT verifier token_head' do
    let(:jwt_validator) do
      make_jwt_validator
    end

    it 'should parse the head of a valid JWT' do
      expect(jwt_validator.token_head(make_hs256_token)[:alg]).to eq('HS256')
    end

    it 'should fail parsing the head of a blank JWT' do
      expect(jwt_validator.token_head('')).to eq({})
    end

    it 'should fail parsing the head of an invalid JWT' do
      expect(jwt_validator.token_head('.')).to eq({})
    end

    it 'should throw an exception for invalid JSON' do
      expect do
        jwt_validator.token_head('QXV0aDA=')
      end.to raise_error(JSON::ParserError)
    end
  end

  describe 'JWT verifier jwks_public_cert' do
    let(:jwt_validator) do
      make_jwt_validator
    end

    it 'should return a public_key' do
      x5c = jwks[:keys].first[:x5c].first
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
    let(:jwt_validator) do
      make_jwt_validator
    end

    before do
      stub_jwks
    end

    it 'should return a key' do
      expect(jwt_validator.jwks_key(:alg, jwks_kid)).to eq('RS256')
    end

    it 'should return an x5c key' do
      expect(jwt_validator.jwks_key(:x5c, jwks_kid).length).to eq(1)
    end

    it 'should return nil if there is not key' do
      expect(jwt_validator.jwks_key(:auth0, jwks_kid)).to eq(nil)
    end

    it 'should return nil if the key ID is invalid' do
      expect(jwt_validator.jwks_key(:alg, "#{jwks_kid}_invalid")).to eq(nil)
    end
  end

  describe 'JWT verifier custom issuer' do
    context 'same as domain' do
      let(:jwt_validator) do
        make_jwt_validator(opt_issuer: domain)
      end

      it 'should have the correct issuer' do
        expect(jwt_validator.issuer).to eq('https://samples.auth0.com/')
      end

      it 'should have the correct domain' do
        expect(jwt_validator.issuer).to eq('https://samples.auth0.com/')
      end
    end

    context 'different from domain' do
      let(:jwt_validator) do
        make_jwt_validator(opt_issuer: 'different.auth0.com')
      end

      it 'should have the correct issuer' do
        expect(jwt_validator.issuer).to eq('https://different.auth0.com/')
      end

      it 'should have the correct domain' do
        expect(jwt_validator.domain).to eq('https://samples.auth0.com/')
      end
    end
  end

  describe 'JWT verifier verify' do
    let(:jwt_validator) do
      make_jwt_validator
    end

    before do
      stub_jwks
      stub_dummy_jwks
    end

    it 'should fail with missing issuer' do
      expect do
        jwt_validator.verify(make_hs256_token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Issuer (iss) claim must be a string present in the ID token"
      }))
    end

    it 'should fail with invalid issuer' do
      payload = {
        iss: 'https://auth0.com/'
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Issuer (iss) claim mismatch in the ID token, expected (https://samples.auth0.com/), found (https://auth0.com/)"
      }))
    end

    it 'should fail when subject is missing' do
      payload = {
        iss: "https://#{domain}/",
        sub: ''
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Subject (sub) claim must be a string present in the ID token"
      }))
    end

    it 'should fail with missing audience' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub'
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Audience (aud) claim must be a string or array of strings present in the ID token"
      }))
    end

    it 'should fail with invalid audience' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: 'Auth0'
      }
      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Audience (aud) claim mismatch in the ID token; expected #{client_id} but found Auth0"
      }))
    end

    it 'should fail when missing expiration' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Expiration time (exp) claim must be a number present in the ID token"
      }))
    end

    it 'should fail when past expiration' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: past_timecode
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Expiration time (exp) claim error in the ID token; current time (#{Time.now}) is after expiration time (#{Time.at(past_timecode + 60)})"
      }))
    end

    it 'should fail when missing iat' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: future_timecode
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Issued At (iat) claim must be a number present in the ID token"
      }))
    end

    it 'should fail when authorize params has nonce but nonce is missing in the token' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token, { nonce: 'noncey' })
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Nonce (nonce) claim must be a string present in the ID token"
      }))
    end

    it 'should fail when authorize params has nonce but token nonce does not match' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode,
        nonce: 'mismatch'
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token, { nonce: 'noncey' })
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Nonce (nonce) claim value mismatch in the ID token; expected (noncey), found (mismatch)"
      }))
    end
    
    it 'should fail when “aud” is an array of strings and azp claim is not present' do
      aud = [
        client_id,
        "https://#{domain}/userinfo"
      ]
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: aud,
        exp: future_timecode,
        iat: past_timecode
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values"
      }))
    end

    it 'should fail when "azp" claim doesnt match the expected aud' do
      aud = [
        client_id,
        "https://#{domain}/userinfo"
      ]
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: aud,
        exp: future_timecode,
        iat: past_timecode,
        azp: 'not_expected'
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Authorized Party (azp) claim mismatch in the ID token; expected (#{client_id}), found (not_expected)"
      }))
    end

    it 'should fail when “max_age” sent on the authentication request and this claim is not present' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token, { max_age: 60 })
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified"
      }))
    end

    it 'should fail when “max_age” sent on the authentication request and this claim added the “max_age” value doesn’t represent a date in the future' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode,
        auth_time: past_timecode
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token, { max_age: 60 })
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (#{Time.now}) is after last auth time (#{Time.at(past_timecode + 60 + 60)})"
      }))
    end

    it 'should verify a valid HS256 token with multiple audiences' do
      audience = [
        client_id,
        "https://#{domain}/userinfo"
      ]
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: audience,
        exp: future_timecode,
        iat: past_timecode,
        azp: client_id
      }
      token = make_hs256_token(payload)
      id_token = jwt_validator.verify(token)
      expect(id_token['aud']).to eq(audience)
    end

    it 'should verify a standard HS256 token' do
      sub = 'abc123'
      payload = {
        iss: "https://#{domain}/",
        sub: sub,
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode
      }
      token = make_hs256_token(payload)
      verified_token = jwt_validator.verify(token)
      expect(verified_token['sub']).to eq(sub)
    end

    it 'should verify a standard RS256 token' do
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
      verified_token = make_jwt_validator(opt_domain: domain).verify(token)
      expect(verified_token['sub']).to eq(sub)
    end
  end

  private

  def make_jwt_validator(opt_domain: domain, opt_issuer: nil)
    opts = OpenStruct.new(
      domain: opt_domain,
      client_id: client_id,
      client_secret: client_secret
    )
    opts[:issuer] = opt_issuer unless opt_issuer.nil?

    OmniAuth::Auth0::JWTValidator.new(opts)
  end

  def make_hs256_token(payload = nil)
    payload = { sub: 'abc123' } if payload.nil?
    JWT.encode payload, client_secret, 'HS256'
  end

  def make_rs256_token(payload = nil)
    payload = { sub: 'abc123' } if payload.nil?
    JWT.encode payload, rsa_private_key, 'RS256', kid: jwks_kid
  end

  def make_cert(private_key)
    cert = OpenSSL::X509::Certificate.new
    cert.issuer = OpenSSL::X509::Name.parse('/C=BE/O=Auth0/OU=Auth0/CN=Auth0')
    cert.subject = cert.issuer
    cert.not_before = Time.now
    cert.not_after = Time.now + 365 * 24 * 60 * 60
    cert.public_key = private_key.public_key
    cert.serial = 0x0
    cert.version = 2

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.extensions = [
      ef.create_extension('basicConstraints', 'CA:TRUE', true),
      ef.create_extension('subjectKeyIdentifier', 'hash')
    ]
    cert.add_extension ef.create_extension(
      'authorityKeyIdentifier',
      'keyid:always,issuer:always'
    )

    cert.sign private_key, OpenSSL::Digest::SHA1.new
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
end
