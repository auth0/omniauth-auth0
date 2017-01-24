require 'spec_helper'

RSpec.shared_examples 'site has valid domain url' do |url|
  it { expect(subject.site).to eq(url) }
end

describe OmniAuth::Strategies::Auth0 do
  let(:client_id) { 'CLIENT_ID' }
  let(:client_secret) { 'CLIENT_SECRET' }
  let(:domain_url) { 'https://samples.auth0.com' }
  let(:app) do
    lambda do
      [200, {}, ['Hello.']]
    end
  end
  let(:auth0) do
    OmniAuth::Strategies::Auth0.new(app, client_id, client_secret, domain_url)
  end

  describe 'client_options' do
    let(:subject) { auth0.client }

    context 'domain with https' do
      let(:domain_url) { 'https://samples.auth0.com' }
      it_behaves_like 'site has valid domain url', 'https://samples.auth0.com'
    end

    context 'domain with http' do
      let(:domain_url) { 'http://mydomain.com' }
      it_behaves_like 'site has valid domain url', 'http://mydomain.com'
    end

    context 'domain with host only' do
      let(:domain_url) { 'samples.auth0.com' }
      it_behaves_like 'site has valid domain url', 'https://samples.auth0.com'
    end

    it 'should have correct authorize path' do
      expect(subject.options[:authorize_url]).to eq('/authorize')
    end

    it 'should have the correct userinfo path' do
      expect(subject.options[:userinfo_url]).to eq('/userinfo')
    end

    it 'should have the correct token path' do
      expect(subject.options[:token_url]).to eq('/oauth/token')
    end
  end

  describe 'options' do
    let(:subject) { auth0.options }

    it 'should have the correct client_id' do
      expect(subject[:client_id]).to eq(client_id)
    end

    it 'should have the correct client secret' do
      expect(subject[:client_secret]).to eq(client_secret)
    end
    it 'should have correct domain' do
      expect(subject[:domain]).to eq(domain_url)
    end
  end
end
