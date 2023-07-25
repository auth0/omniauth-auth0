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
  let(:valid_jwks_kid) { 'NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg' }

  let(:rsa_private_key) do
    OpenSSL::PKey::RSA.generate 2048
  end

  let(:valid_jwks) do
    {
      keys: [
        {
          kid: valid_jwks_kid,
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

  describe 'JWT verifier jwks key parsing' do
    let(:jwt_validator) do
      make_jwt_validator
    end

    before do
      stub_complete_jwks
    end

    it 'should return a key' do
      expect(jwt_validator.jwks_key(:alg, valid_jwks_kid)).to eq('RS256')
    end

    it 'should return an x5c key' do
      expect(jwt_validator.jwks_key(:x5c, valid_jwks_kid).length).to eq(1)
    end

    it 'should return nil if there is not key' do
      expect(jwt_validator.jwks_key(:auth0, valid_jwks_kid)).to eq(nil)
    end

    it 'should return nil if the key ID is invalid' do
      expect(jwt_validator.jwks_key(:alg, "#{valid_jwks_kid}_invalid")).to eq(nil)
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
      shared_examples_for 'has correct issuer and domain' do
        let(:jwt_validator) { make_jwt_validator(opt_issuer: opt_issuer) }

        it 'should have the correct issuer' do
          expect(jwt_validator.issuer).to eq('https://different.auth0.com/')
        end

        it 'should have the correct domain' do
          expect(jwt_validator.domain).to eq('https://samples.auth0.com/')
        end
      end

      context 'without protocol and trailing slash' do
        let(:opt_issuer) { 'different.auth0.com' }
        it_behaves_like 'has correct issuer and domain'
      end

      context 'with protocol and trailing slash' do
        let(:opt_issuer) { 'https://different.auth0.com/' }
        it_behaves_like 'has correct issuer and domain'
      end
    end
  end

  describe 'JWT verifier verify' do
    let(:jwt_validator) do
      make_jwt_validator
    end

    before do
      stub_complete_jwks
      stub_expected_jwks
    end

    it 'should fail when JWT is nil' do
      expect do
        jwt_validator.verify(nil)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "ID token is required but missing"
      }))
    end

    it 'should fail when JWT is not well-formed' do
      expect do
        jwt_validator.verify('abc.123')
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "ID token could not be decoded"
      }))
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

    it 'should pass when past expiration but within default leeway' do
      exp = Time.now.to_i - 59
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: exp,
        iat: past_timecode
      }

      token = make_hs256_token(payload)
      id_token = jwt_validator.verify(token)
      expect(id_token['exp']).to eq(exp)
    end

    it 'should fail when past expiration and outside default leeway' do
      exp = Time.now.to_i - 61
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: exp,
        iat: past_timecode
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Expiration time (exp) claim error in the ID token; current time (#{Time.now}) is after expiration time (#{Time.at(exp + 60)})"
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

    it 'should fail when “max_age” sent on the authentication request and this claim added the “max_age” value doesn’t represent a date in the future, outside the default leeway' do
      now = Time.now.to_i
      auth_time = now - 121
      max_age = 60
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode,
        auth_time: auth_time
      }

      token = make_hs256_token(payload)
      expect do
        jwt_validator.verify(token, { max_age: max_age })
        # Time.at(auth_time + max_age + leeway
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (#{Time.now}) is after last auth time (#{Time.at(auth_time + max_age + 60)})"
      }))
    end

    it 'should verify when “max_age” sent on the authentication request and this claim added the “max_age” value doesn’t represent a date in the future, outside the default leeway' do
      now = Time.now.to_i
      auth_time = now - 119
      max_age = 60
      payload = {
        iss: "https://#{domain}/",
        sub: 'sub',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode,
        auth_time: auth_time
      }

      token = make_hs256_token(payload)
      id_token = jwt_validator.verify(token, { max_age: max_age })
      expect(id_token['auth_time']).to eq(auth_time)
    end

    context 'Organization claim validation' do
      it 'should fail when authorize params has organization but org_id is missing in the token' do
        payload = {
          iss: "https://#{domain}/",
          sub: 'sub',
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode
        }

        token = make_hs256_token(payload)
        expect do
          jwt_validator.verify(token, { organization: 'org_123' })
        end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
          message: "Organization Id (org_id) claim must be a string present in the ID token"
        }))
      end

      it 'should fail when authorize params has organization but org_name is missing in the token' do
        payload = {
          iss: "https://#{domain}/",
          sub: 'sub',
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode
        }

        token = make_hs256_token(payload)
        expect do
          jwt_validator.verify(token, { organization: 'my-organization' })
        end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and(having_attributes({
          message: 'Organization Name (org_name) claim must be a string present in the ID token'
        })))
      end

      it 'should fail when authorize params has organization but token org_id does not match' do
        payload = {
          iss: "https://#{domain}/",
          sub: 'sub',
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode,
          org_id: 'org_5678'
        }

        token = make_hs256_token(payload)
        expect do
          jwt_validator.verify(token, { organization: 'org_1234' })
        end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and(having_attributes({
          message: "Organization Id (org_id) claim value mismatch in the ID token; expected 'org_1234', found 'org_5678'"
        })))
      end

      it 'should fail when authorize params has organization but token org_name does not match' do
        payload = {
          iss: "https://#{domain}/",
          sub: 'sub',
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode,
          org_name: 'another-organization'
        }

        token = make_hs256_token(payload)
        expect do
          jwt_validator.verify(token, { organization: 'my-organization' })
        end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and(having_attributes({
          message: "Organization Name (org_name) claim value mismatch in the ID token; expected 'my-organization', found 'another-organization'"
        })))
      end

      it 'should not fail when correctly given an organization ID' do
        payload = {
          iss: "https://#{domain}/",
          sub: 'sub',
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode,
          org_id: 'org_1234'
        }

        token = make_hs256_token(payload)
        jwt_validator.verify(token, { organization: 'org_1234' })
      end

      it 'should not fail when correctly given an organization name' do
        payload = {
          iss: "https://#{domain}/",
          sub: 'sub',
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode,
          org_name: 'my-organization'
        }

        token = make_hs256_token(payload)
        jwt_validator.verify(token, { organization: 'my-organization' })
      end

      it 'should not fail when given an organization name in a different casing' do
        payload = {
          iss: "https://#{domain}/",
          sub: 'sub',
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode,
          org_name: 'my-organization'
        }

        token = make_hs256_token(payload)
        jwt_validator.verify(token, { organization: 'MY-ORGANIZATION' })
      end
    end
    it 'should fail for RS256 token when kid is incorrect' do
      domain = 'example.org'
      sub = 'abc123'
      payload = {
        sub: sub,
        exp: future_timecode,
        iss: "https://#{domain}/",
        iat: past_timecode,
        aud: client_id
      }
      invalid_kid = 'invalid-kid'
      token = make_rs256_token(payload, invalid_kid)
      expect do
        verified_token = make_jwt_validator(opt_domain: domain).verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Could not find a public key for Key ID (kid) 'invalid-kid'"
      }))
    end

    it 'should fail when RS256 token has invalid signature' do
      domain = 'example.org'
      sub = 'abc123'
      payload = {
        sub: sub,
        exp: future_timecode,
        iss: "https://#{domain}/",
        iat: past_timecode,
        aud: client_id
      }
      token = make_rs256_token(payload) + 'bad'
      expect do
        verified_token = make_jwt_validator(opt_domain: domain).verify(token)
      end.to raise_error(an_instance_of(JWT::VerificationError).and having_attributes({
        message: "Signature verification failed"
      }))
    end

    it 'should fail when algorithm is not RS256 or HS256' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'abc123',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode
      }
      token = JWT.encode payload, 'secret', 'HS384'
      expect do
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
        message: "Signature algorithm of HS384 is not supported. Expected the ID token to be signed with RS256 or HS256"
      }))
    end

    it 'should fail when HS256 token has invalid signature' do
      payload = {
        iss: "https://#{domain}/",
        sub: 'abc123',
        aud: client_id,
        exp: future_timecode,
        iat: past_timecode
      }
      token = make_hs256_token(payload, 'bad_secret')
      expect do
        # validator is configured to use "CLIENT_SECRET" by default
        jwt_validator.verify(token)
      end.to raise_error(an_instance_of(JWT::VerificationError))
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
        aud: client_id
      }
      token = make_rs256_token(payload)
      verified_token = make_jwt_validator(opt_domain: domain).verify(token)
      expect(verified_token['sub']).to eq(sub)
    end

    it 'should verify a HS256 JWT signature when calling verify signature directly' do
      sub = 'abc123'
        payload = {
          iss: "https://#{domain}/",
          sub: sub,
          aud: client_id,
          exp: future_timecode,
          iat: past_timecode
        }
        token = make_hs256_token(payload)
        verified_token_signature = jwt_validator.verify_signature(token)
        expect(verified_token_signature[0]).to eq('CLIENT_SECRET')
        expect(verified_token_signature[1]).to eq('HS256')
    end

    it 'should verify a RS256 JWT signature verify signature directly' do
      domain = 'example.org'
      sub = 'abc123'
      payload = {
        sub: sub,
        exp: future_timecode,
        iss: "https://#{domain}/",
        iat: past_timecode,
        aud: client_id
      }
      token = make_rs256_token(payload)
      verified_token_signature = make_jwt_validator(opt_domain: domain).verify_signature(token)
      expect(verified_token_signature.length).to be(2)
      expect(verified_token_signature[0]).to be_a(OpenSSL::PKey::RSA)
      expect(verified_token_signature[1]).to eq('RS256')
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

  def make_hs256_token(payload = nil, secret = nil)
    payload = { sub: 'abc123' } if payload.nil?
    secret = client_secret if secret.nil?
    JWT.encode payload, secret, 'HS256'
  end

  def make_rs256_token(payload = nil, kid = nil)
    payload = { sub: 'abc123' } if payload.nil?
    kid = valid_jwks_kid if kid.nil?
    JWT.encode payload, rsa_private_key, 'RS256', kid: kid
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

  def stub_complete_jwks
    stub_request(:get, 'https://samples.auth0.com/.well-known/jwks.json')
      .to_return(
        headers: { 'Content-Type' => 'application/json' },
        body: jwks.to_json,
        status: 200
      )
  end

  def stub_expected_jwks
    stub_request(:get, 'https://example.org/.well-known/jwks.json')
      .to_return(
        headers: { 'Content-Type' => 'application/json' },
        body: valid_jwks,
        status: 200
      )
  end
end
