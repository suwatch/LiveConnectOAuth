LiveConnectOAuth
================
This demonstrates adding live-id authentication to your site using live connect oauth2.0.

  - Create [the live application](https://account.live.com/developers/applications)
  - Select `Api Settings`, enter 2 urls as Redirect URLs.  Note: replace the `mysite` with your sitename.
    - http://mysite.azurewebsites.net/login/callback
    - http://mysite.azurewebsites.net/logout/complete
  - Select `App Settings`, ..
    - Copy the value of Client ID and paste it as `LiveConnectClientId` appSettings.
    - Copy the value of Client Secret and paste it as `LiveConnectClientSecret` appSettings.

Try browsing to http://mysite.azurewebsites.net/.
