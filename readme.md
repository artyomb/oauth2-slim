# OAuth 2.0 

### Authorization Request
```http
GET /oauth2/authorize?
  response_type=code&
  client_id=abc123&
  redirect_uri=https://yourapp.com/callback&
  scope=read_profile email&
  state=xyz123
```

### Token Request
```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=abcd1234&
redirect_uri=https://yourapp.com/callback&
client_id=abc123&
client_secret=supersecret&
code_verifier=d1f2e3g4h5i6j7k8l9
```

# Client configuration example
Grafana docker image configuration example using environment variables
```ruby
# Grafana
GF_AUTH_GENERIC_OAUTH_ENABLED: true
GF_AUTH_GENERIC_OAUTH_NAME: 'OAuth2 Slim'
GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP: true
GF_AUTH_GENERIC_OAUTH_CLIENT_ID: '<clien id>'
GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: '<client secret>'
GF_AUTH_GENERIC_OAUTH_SCOPES: 'openid email profile offline_access roles'
GF_AUTH_GENERIC_OAUTH_USE_REFRESH_TOKEN: true
GF_AUTH_GENERIC_OAUTH_EMAIL_ATTRIBUTE_PATH: 'email'
GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH: 'username'
GF_AUTH_GENERIC_OAUTH_NAME_ATTRIBUTE_PATH: 'full_name'
GF_AUTH_GENERIC_OAUTH_AUTH_URL: "https://auth.#{ENV['MAIN_DOMAIN']}/auth" # "https://<PROVIDER_DOMAIN>/realms/<REALM_NAME>/protocol/openid-connect/auth",
GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "https://auth.#{ENV['MAIN_DOMAIN']}/token" # 'https://<PROVIDER_DOMAIN>/realms/<REALM_NAME>/protocol/openid-connect/token',
GF_AUTH_GENERIC_OAUTH_API_URL: "https://auth.#{ENV['MAIN_DOMAIN']}/userinfo" # 'https://<PROVIDER_DOMAIN>/realms/<REALM_NAME>/protocol/openid-connect/userinfo',
GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "contains(roles[*], 'admin') && 'Admin' || contains(roles[*], 'editor') && 'Editor' || 'Viewer'"
GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN: true
```

# Configure JWT authentication
Example is based on Grafana documentation:
https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/jwt/

You can configure Client to accept a JWT token provided in the HTTP header. The token is verified using any of the following:
 - PEM-encoded key file
 - JSON Web Key Set (JWKS) in a local file
 - JWKS provided by the configured JWKS endpoint

This method of authentication is useful for integrating with other systems that
use JWKS but can’t directly integrate with Grafana or if you want to 
use pass-through authentication in an app embedding Client in IFrame.

JMESPath https://jmespath.org/

```ruby
GF_AUTH_JWT_ENABLED: true
GF_AUTH_JWT_HEADER_NAME: 'Authorization'
# Specify a claim to use as a username to sign in.
GF_AUTH_JWT_USERNAME_CLAIM: 'sub'
# Specify a claim to use as an email to sign in.
GF_AUTH_JWT_EMAIL_CLAIM: 'sub'
# auto-create users if they are not already matched
GF_AUTH_JWT_AUTO_SIGN_UP: true
# Specify a nested attribute to use as a username to sign in.
GF_AUTH_JWT_USERNAME_ATTRIBUTE_PATH: 'user.username' # user's login is johndoe
# Specify a nested attribute to use as an email to sign in.
GF_AUTH_JWT_EMAIL_ATTRIBUTE_PATH: 'user.emails[1]' # user's email is professional@email.com

# Verify token using a JSON Web Key Set loaded from https endpoint or JSON file
GF_AUTH_JWT_JWK_SET_URL: 'https://your-auth-provider.example.com/.well-known/jwks.json'
GF_AUTH_JWT_JWK_SET_FILE: '/path/to/jwks.json'

# Cache TTL for data loaded from http endpoint.
GF_AUTH_JWT_CACHE_TTL: '60m'

# By default, only "exp", "nbf" and "iat" claims are validated.
# You might also want to validate that other claims. This can be seen as a required "subset" of a JWT Claims Set.
GF_AUTH_JWT_EXPECT_CLAIMS: '{"iss": "https://your-token-issuer", "your-custom-claim": "foo"}'

GF_AUTH_JWT_ROLE_ATTRIBUTE_PATH: 'role'
GF_AUTH_JWT_ROLE_ATTRIBUTE_PATH: "contains(info.roles[*], 'admin') && 'Admin' || contains(info.roles[*], 'editor') && 'Editor' || 'Viewer'"
GF_AUTH_JWT_ALLOW_ASSIGN_GRAFANA_ADMIN: true
```


# Token body example based on Keycloak implementation

```json
{
  "exp": 1724744688,
  "iat": 1724708688,
  "jti": "c79fb239-387f-405c-b241-6559abeafb41",
  "iss": "http://keycloak.next:8080/realms/node",
  "aud": [
    "realm-management",
    "resource-aircraft",
    "account",
    "resource-calculation"
  ],
  "sub": "2961dac4-59f3-4632-95fb-530610a24741",
  "typ": "Bearer",
  "azp": "graph-auth",
  "session_state": "1963dd89-07df-4fb9-85ff-f6331f8b55be",
  "scope": "short-roles email profile",
  "sid": "1963dd89-07df-4fb9-85ff-f6331f8b55be",
  "roles": {
    "realm-management": [
      "view-realm", "view-identity-providers",
      "manage-identity-providers", "impersonation",
      "realm-admin", "create-client", "manage-users",
      "query-realms", "view-authorization", "query-clients",
      "query-users", "manage-events", "manage-realm",
      "view-events", "view-users", "view-clients",
      "manage-authorization", "manage-clients", "query-groups"
    ],
    "resource-aircraft": [
      "read_creator",
      "read_own",
      "read_group"
    ],
    "account": [
      "manage-account",
      "manage-account-links",
      "view-profile"
    ],
    "resource-calculation": [
      "read_creator"
    ]
  },
  "name": "Admin",
  "groups": [
    "/admins",
    "/companies/monitorsoft"
  ],
  "username": "admin"
}
```
