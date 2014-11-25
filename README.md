LiveConnectOAuth
================
This demonstrates adding live-id authentication to your site using live connect oauth2.0.

  - Create [the live application](https://account.live.com/developers/applications).  
    - On `App Settings` section, take note of Client ID and Secret.  You will need this info in next step.
    
  - Deploy this repository to Azure by clicking <a href="https://azuredeploy.net/" target="_blank"><img src="http://azuredeploy.net/deploybutton.png"/></a>
    - Choose `Directory`, `Subscription` and `Location` appropriately.
    - Change the `Site Name` to something you can recognize.  
    - Enter live application Client ID as `LiveConnectClientId` value.
    - Enter live application Client Secret as `LiveConnectClientSecret` value.
    - Click Next and Deploy to Azure WebSites.  
    - The site url will be `http://{sitename}.azurewebsites.net/`.  Note: `{sitename}` is the `Site Name` you pick above.
    
  -  On Api Settings section of [the live application](https://account.live.com/developers/applications).  Add below urls as `Redirect URLs`
    - http://{sitename}.azurewebsites.net/login/callback
    - http://{sitename}.azurewebsites.net/logout/complete

Try browsing to http://{sitename}.azurewebsites.net/.
