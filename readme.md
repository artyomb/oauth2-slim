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