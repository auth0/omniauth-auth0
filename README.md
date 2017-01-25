[![Build Status](https://travis-ci.org/auth0/omniauth-auth0.svg)](https://travis-ci.org/auth0/omniauth-auth0)

# OmniAuth Auth0

This is the official [OmniAuth](https://github.com/intridea/omniauth) strategy for authenticating to [Auth0](https://auth0.com).

## Installing

Add to your `Gemfile`:

```ruby
gem 'omniauth-auth0'
```

Then `bundle install`.

## Usage

### Rails

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :auth0, ENV['AUTH0_CLIENT_ID'], ENV['AUTH0_CLIENT_SECRET'], ENV['AUTH0_DOMAIN']
end
```

Then to redirect to your tenant's hosted login page:

```ruby
redirect_to '/auth/auth0'
```

### Sinatra

```ruby
use OmniAuth::Builder do
  provider :auth0, ENV['AUTH0_CLIENT_ID'], ENV['AUTH0_CLIENT_SECRET'], ENV['AUTH0_DOMAIN']
end
```

Then to redirect to your tenant's hosted login page:

```ruby
redirect to('/auth/auth0')
```

> You can customize your hosted login page in your [Auth0 Dashboard](https://manage.auth0.com/#/login_page)

### Auth parameters

To send additional parameters during login you can specify them when you register the provider

```ruby
provider 
  :auth0,
  ENV['AUTH0_CLIENT_ID'],
  ENV['AUTH0_CLIENT_SECRET'],
  ENV['AUTH0_DOMAIN'],
  {
    authorize_params: {
      scope: 'openid read:users write:order',
      audience: 'https://mydomain/api'
    }
  }
```

that will tell it to send those parameters on every Auth request.

Or you can do it for a specific Auth request by adding them in the query parameter of the redirect url:

```ruby
redirect_to '/auth/auth0?connection=google-oauth2'
```

### Auth Hash

Auth0 strategy will have the standard OmniAuth hash attributes:

- provider: the name of the strategy, in this case `auth0`
- uid: the user identifier
- info: the result of the call to /userinfo using OmniAuth standard attributes
- credentials: Auth0 tokens, at least will have an access_token but can eventually have refresh_token and/or id_token
- extra: Additional info obtained from calling /userinfo in the attribute `raw_info`

```ruby
	{
	  :provider => 'auth0',
	  :uid => 'google-oauth2|this-is-the-google-id',
	  :info => {
	    :name => 'John Foo',
	    :email => 'johnfoo@example.org',
	    :nickname => 'john',
	    :image => 'https://example.org/john.jpg'
	  },
	  :credentials => {
	    :token => 'XdDadllcas2134rdfdsI',
	    :expires_at => 1485373937,
        :expires => true,
        :refresh_token => 'aKNajdjfj123nBasd',
	    :id_token => 'eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBGb28ifQ.lxAiy1rqve8ZHQEQVehUlP1sommPHVJDhgPgFPnDosg',
	    :token_type => 'bearer',
	  },
	  :extra => {
	    :raw_info => {
	      :email => 'johnfoo@example.org',
	      :email_verified => 'true',
	      :name => 'John Foo',
	      :picture => 'https://example.org/john.jpg',
	      :user_id => 'google-oauth2|this-is-the-google-id',
	      :nickname => 'john',
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

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
