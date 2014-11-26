# OmniAuth Auth0

This is the official OmniAuth strategy for authenticating to [Auth0](https://auth0.com).

## Installing

Add to your `Gemfile`:

```ruby
gem 'omniauth-auth0'
```

Then `bundle install`.

## Basic Usage

### Rails

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :auth0, ENV['CLIENT_ID'], ENV['CLIENT_SECRET'], ENV['YOUR_NAMESPACE']
end
```

### Sinatra

```ruby
use OmniAuth::Builder do
  provider :auth0, ENV['CLIENT_ID'], ENV['CLIENT_SECRET'], ENV['YOUR_NAMESPACE']
end
```

> Optional you can set the `:provider_ignores_state` passing a fourth parameter. By default it is true.

### Login widget

Integrate the widget in one of your pages as described [here](http://docs.auth0.com/widget) or use links as described in the same link.

### Auth Hash

```ruby
	{
	  :provider => 'auth0',
	  :uid => 'google-oauth2|this-is-the-google-id',
	  :info => {
	    :name => 'John Foo',
	    :email => 'johnfoo@example.org',
	    :nickname => 'john',
	    :first_name => 'John',
	    :last_name => 'Foo',
	    :location => 'en',
	    :image => 'https://example.org/john.jpg'
	  },
	  :credentials => {
	    :token => 'XdDadllcas2134rdfdsI',
	    :expires => 'false',
	    :id_token => 'eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBGb28ifQ.lxAiy1rqve8ZHQEQVehUlP1sommPHVJDhgPgFPnDosg',
	    :token_type => 'bearer',
	  },
	  :extra => {
	    :raw_info => {
	      :email => 'johnfoo@example.org',
	      :email_verified => 'true',
	      :name => 'John Foo',
	      :given_name => 'John',
	      :family_name => 'Foo',
	      :picture => 'https://example.org/john.jpg',
	      :gender => 'male',
	      :locale => 'en',
	      :clientID => 'nUBkskdaYdsaxK2n9',
	      :user_id => 'google-oauth2|this-is-the-google-id',
	      :nickname => 'john',
	      :identities => [{
	        :access_token => 'this-is-the-google-access-token',
	        :provider => 'google-oauth2',
	        :expires_in => '3599',
	        :user_id => 'this-is-the-google-id',
	        :connection => 'google-oauth2',
	        :isSocial => 'true',
	      }],
	      :created_at: '2014-07-15T17:19:50.387Z'
	    }
	  }
	}
```

### ActionDispatch::Cookies::CookieOverflow issue

If you are getting this error it means that you are using Cookie sessions and since you are storing the whole profile it overflows the max-size of 4K.

You can change to use In-Memory store for development as follows:

	# /config/initializers/session_store.rb
	CrazyApp::Application.config.session_store :cache_store

	# /config/environments/development.rb
	config.cache_store = :memory_store

## Documentation

For more information about [auth0](http://auth0.com) contact our [documentation page](http://docs.auth0.com/).

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.
