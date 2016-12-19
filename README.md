
This plugin adds the "Sign-in with Google / Facebook / Github / Linkedin / Windows Live / id.projectkit.net" buttons on the login page. The first time the user login with a social account, a new Moodle account is created.

It forked from [moodle-auth_googleoauth2](https://github.com/mouneyrac/moodle-auth_googleoauth2) 

And this is [Offcial moodle plugin website](https://moodle.org/plugins/pluginversion.php?id=12523)    

### Requirements

PHP 5.5

### Installation:
1. Clone plugin: 

    * Go to folder moodle\auth\

    * Git: git clone https://github.com/fproject/moodle-auth_googleoauth2.git

    * Rename dir moodle-auth_googleoauth2 to googleoauth2.

2. Config, go to folder googleoauth2:

    * The first, chang config.php
    
    * The second: composer update
 
3. Enable plugin:

    * Login Moodle as admin.
    
    * Go to Site administration/ Advanced features / Plugins / Authentication / Manage authentication: Enable Oauth2 plugin.
    
    * In setting of Oauth2, insert clientId and secret whose your registered with id.projectkit.net
    
    * Ok, good luck :)
    
### Update:

1. Login with accesstoken

    * You can login moodle with accesstoken, example about structure of link: 
    
    http://localhost/moodle/login/index.php?authprovider=vp&accessToken=XXXX

2. End point revice revokeToken

    * Endpoint address: 
    
    http://localhost/moodle/login/index.php?revokeToken=XXXX