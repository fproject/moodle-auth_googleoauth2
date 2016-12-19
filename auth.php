<?php
// This file is part of Oauth2 authentication plugin for Moodle.
//
// Oauth2 authentication plugin for Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Oauth2 authentication plugin for Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Oauth2 authentication plugin for Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @author Jerome Mouneyrac
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 *
 * Authentication Plugin: Google/Facebook/Messenger Authentication
 * If the email doesn't exist, then the auth plugin creates the user.
 * If the email exist (and the user has for auth plugin this current one),
 * then the plugin login the user related to this email.
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    // It must be included from a Moodle page.
}
global $CFG;
require_once($CFG->libdir . '/authlib.php');
require_once($CFG->dirroot . '/auth/googleoauth2/vendor/autoload.php');
require_once($CFG->dirroot . '/auth/googleoauth2/lib.php');
require_once($CFG->dirroot . '/auth/googleoauth2/config.php');
use Guzzle\Service\Client as GuzzleClient;

/**
 * Google/Facebook/Messenger Oauth2 authentication plugin.
 */
class auth_plugin_googleoauth2 extends auth_plugin_base
{

    const CRYPTO_ALG = 'RS256';
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->authtype = 'googleoauth2';
        $this->roleauth = 'auth_googleoauth2';
        $this->errorlogtag = '[AUTH GOOGLEOAUTH2] ';
        $this->config = get_config('auth/googleoauth2');
    }

    /**
     * Prevent authenticate_user_login() to update the password in the DB
     * @return boolean
     */
    public function prevent_local_passwords()
    {
        return true;
    }

    /**
     * Authenticates user against the selected authentication provide (Google, Facebook...)
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password)
    {
        global $DB, $CFG;

        // Retrieve the user matching username.
        $user = $DB->get_record('user', array('username' => $username,
            'mnethostid' => $CFG->mnet_localhost_id));

        // Username must exist and have the right authentication method.
        if (!empty($user) && ($user->auth == 'googleoauth2')) {
            $code = optional_param('authprovider', false, PARAM_TEXT);
            $accesstoken = optional_param('accesstoken', '', PARAM_TEXT);
            if (empty($code) && empty($accesstoken)) {
                return false;
            }
            return true;
        }
        
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    public function is_internal()
    {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    public function can_change_password()
    {
        return false;
    }

    /**
     * Verify and decode a JWT token
     * @param string $token the encoded JWT token
     * @return \stdClass the payload data of JWT token
     */
    public function verifyAndDecodeToken($token)
    {
        $payload = \Firebase\JWT\JWT::decode($token, $this->getPublicKey(), [self::CRYPTO_ALG]);
        $payload -> revoked = false;
        if ($this->checkRevokedToken($token, $payload->exp))
            $payload -> revoked = true;
        return $payload;
    }

    /**
     * Check if token is revoked
     * @param string $token 
     * @param DateTime $time 
     * @return bool true if the token is revoked
     */
    public function checkRevokedToken($token, $time)
    {
        global $CFG;
        $cacheFile = $CFG->dirroot . '/auth/googleoauth2/cache/revokeToken/' . sha1($token) . '.html';

        if (file_exists($cacheFile) && time() <= $time && file_get_contents($cacheFile) == sha1($token))
        {
            return true;
        } else {
            return false;
        }
    }

    /**
     * The public key in decoded JWK format used for Token encode/decode
     * @return array|mixed
     * @throws moodle_exception
     */

    public function getPublicKey()
    {
        global $CFG;
        $client = new GuzzleClient();
        if ($client == null){
            throw new moodle_exception('Nullclient', 'auth_googleoauth2');
        } else {
            $client->setBaseUrl($CFG->jwkUrl);
        }
        $request = $client->get(null, null,array())->send();
        $jwk = $request->getBody();
        $jwkDecode = json_decode($jwk);
        $publicKey = \Firebase\JWT\JWK::parseKeySet($jwkDecode);
        return $publicKey;
    }

    /**
     * Authentication hook - is called every time user hit the login page
     */
    public function loginpage_hook()
    {
        global $USER, $SESSION, $CFG, $DB;

        // Check the Google authorization code.
        $authorization = optional_param('code', '', PARAM_TEXT);
        // Check the Google authorization accesstoken.
        $accessToken = optional_param('accessToken', '', PARAM_TEXT);
        // Check the Google authorization revoketoken.
        $revokeToken = optional_param('revokeToken', '', PARAM_TEXT);

        if(!empty($revokeToken)){
            $this->addRevokeToken($revokeToken);
        }

        if (!empty($authorization) || !empty($accessToken)) {

            $authProvider = required_param('authprovider', PARAM_ALPHANUMEXT);
            require_once($CFG->dirroot . '/auth/googleoauth2/classes/provider/' . $authProvider . '.php');
            $providerClassName = 'provideroauth2' . $authProvider;

            /** @var provideroauth2vp $provider */
            $provider = new $providerClassName();
            /** @var \League\OAuth2\Client\Token\AccessToken $token */
            $token = null;
            if(!empty($accessToken)) {
                $refreshToken = '';
                $tokenExpires = '';
                $tokenArray = array('access_token' => $accessToken, 'refreshToken' => $refreshToken , 'expires' => $tokenExpires);
                $token = new \League\OAuth2\Client\Token\AccessToken($tokenArray);

            } else {

                $token = $provider->getAccessToken('authorization_code', ['code' => $authorization]);
                // Try to get an access token (using the authorization code grant).
                $accessToken = $token->accessToken;
                $refreshToken = $token->refreshToken;
                $tokenExpires = $token->expires;
            }

            /**
             * VerifyAccessToken
             */
            $payload = $this -> verifyAndDecodeToken($accessToken);

            if ($CFG->issVerify != $payload->iss || $CFG->scopes != $payload->scp || time() > $payload->exp || $payload->revoked == true ){
                // Throw an error if accesstoken is not verified.
                throw new moodle_exception('verifiedAccesstokenfaild', 'auth_googleoauth2');
            }

            session_start();
            $_SESSION['ACCESSTOKEN'] = $accessToken;

            // With access token request by curl the email address.
            if (!empty($accessToken)) {

                $userEmail = '';

                try {
                    $provider->authorizationHeader = 'Bearer';
                    // We got an access token, let's now get the user's details.
                    $userDetails = $provider->getUserDetails($token);

                    // Use these details to create a new profile.
                    switch ($authProvider) {
                        case 'battlenet':
                            // Battlenet as no email notion.
                            // TODO: need to check the idp table for matching user and request user to add his email.
                            // TODO: It will be similar logic for twitter.
                            $userEmail = $userDetails->id . '@fakebattle.net';
                            break;
                        case 'github':
                            $userEmails = $provider->getUserEmails($token);
                            // Going to try to find someone with a similar email using googleoauth2 auth.
                            $fallbackUserEmail = '';
                            foreach ($userEmails as $gitHubUserEmail) {
                                if ($gitHubUserEmail->verified) {
                                    if ($DB->record_exists('user',
                                        array('auth' => 'googleoauth2', 'email' => $gitHubUserEmail->email))
                                    ) {
                                        $userEmail = $gitHubUserEmail->email;
                                    }
                                    $fallbackUserEmail = $gitHubUserEmail->email;
                                }
                            }
                            // If we didn't find anyone then we take a verified email address.
                            if (empty($userEmail)) {
                                $userEmail = $fallbackUserEmail;
                            }
                            break;
                        case 'vk':
                            // VK doesn't return the email address?
                            if ($userDetails->uid) {
                                $userEmail = 'id' . $userDetails->uid . '@vkmessenger.com';
                            };
                            break;
                        default:
                            $userEmail = $userDetails->email;
                            break;
                    }
                } catch (Exception $e) {
                    // Failed to get user details.
                    throw new moodle_exception('faileduserdetails', 'auth_googleoauth2');
                }

                // Prohibit login if email belongs to the prohibited domain.
                if ($err = email_is_not_allowed($userEmail)) {
                    throw new moodle_exception($err, 'auth_googleoauth2');
                }

                // If email not existing in user database then create a new username (userX).
                if (empty($userEmail) || $userEmail != clean_param($userEmail, PARAM_EMAIL)) {
                    throw new moodle_exception('couldnotgetuseremail', 'auth_googleoauth2');
                    // TODO: display a link for people to retry.
                }
                // Get the user.
                // Don't bother with auth = googleoauth2 because authenticate_user_login() will fail it if it's not 'googleoauth2'.
                $user = $DB->get_record('user',
                    array('email' => $userEmail, 'deleted' => 0, 'mnethostid' => $CFG->mnet_localhost_id));

                // Create the user if it doesn't exist.
                if (empty($user)) {
                    // Deny login if setting "Prevent account creation when authenticating" is on.
                    if ($CFG->authpreventaccountcreation) {
                        throw new moodle_exception("noaccountyet", "auth_googleoauth2");
                    }

                    // Get following incremented username.
                    $googleUserPrefix = core_text::strtolower(get_config('auth/googleoauth2', 'googleuserprefix'));
                    $lastUserNumber = get_config('auth/googleoauth2', 'lastusernumber');
                    $lastUserNumber = empty($lastUserNumber) ? 1 : $lastUserNumber + 1;
                    // Check the user doesn't exist.
                    $nextuser = $DB->record_exists('user', array('username' => $googleUserPrefix . $lastUserNumber));
                    while ($nextuser) {
                        $lastUserNumber++;
                        $nextuser = $DB->record_exists('user', array('username' => $googleUserPrefix . $lastUserNumber));
                    }
                    set_config('lastusernumber', $lastUserNumber, 'auth/googleoauth2');
                    $username = $googleUserPrefix . $lastUserNumber;

                    // Retrieve more information from the provider.
                    $newUser = new stdClass();
                    $newUser->email = $userEmail;

                    switch ($authProvider) {
                        case 'battlenet':
                            // Battlenet as no firstname/lastname notion.
                            $newUser->firstname = $userDetails->display_name;
                            $newUser->lastname = '[' . $userDetails->clan_tag . ']';
                            break;
                        case 'github':
                        case 'dropbox':
                            // As Github/Dropbox doesn't provide firstname/lastname, we'll split the name at the first whitespace.
                            $gitHubUserName = explode(' ', $userDetails->name, 2);
                            $newUser->firstname = $gitHubUserName[0];
                            $newUser->lastname = $gitHubUserName[1];
                            break;
                        case 'vp':
                            $newUser->firstname = $userDetails->name;
                            $newUser->lastname = " ";
                            break;
                        default:
                            $newUser->firstname = $userDetails->firstName;
                            $newUser->lastname = $userDetails->lastName;
                            break;
                    }

                    // Some providers allow empty firstname and lastname.
                    if (empty($newUser->firstname)) {
                        $newUser->firstname = get_string('UnknowFirstName', 'auth_googleoauth2');
                    }
                    if (empty($newUser->lastname)) {
                        $newUser->lastname = get_string('UnknowLastName', 'auth_googleoauth2');
                    }

                    // Retrieve country and city if the provider failed to give it.
                    if (!isset($newUser->country) || !isset($newUser->city)) {
                        $googleIpinFodbKey = get_config('auth/googleoauth2', 'googleipinfodbkey');
                        if (!empty($googleIpinFodbKey)) {
                            require_once($CFG->libdir . '/filelib.php');
                            $curl = new curl();
                            $locationData = $curl->get('http://api.ipinfodb.com/v3/ip-city/?key=' .
                                $googleIpinFodbKey . '&ip=' . getremoteaddr() . '&format=json');
                            $locationData = json_decode($locationData);
                        }
                        if (!empty($locationData)) {
                            // TODO: check that countryCode does match the Moodle country code.
                            $newUser->country = isset($newUser->country) ? isset($newUser->country) : $locationData->countryCode;
                            $newUser->city = isset($newUser->city) ? isset($newUser->city) : $locationData->cityName;
                        }
                    }

                    create_user_record($username, '', 'googleoauth2');
                } else {
                    $username = $user->username;
                }

                // Authenticate the user.
                // TODO: delete this log later.
                require_once($CFG->dirroot . '/auth/googleoauth2/lib.php');
                $userId = empty($user) ? 'new user' : $user->id;
                oauth_add_to_log(SITEID, 'auth_googleoauth2', '', '', $username . '/' . $userEmail . '/' . $userId);
                $user = authenticate_user_login($username, null);
                if ($user) {

                    // Set a cookie to remember what auth provider was selected.
                    setcookie('MOODLEGOOGLEOAUTH2_' . $CFG->sessioncookie, $authProvider,
                        time() + (DAYSECS * 60), $CFG->sessioncookiepath,
                        $CFG->sessioncookiedomain, $CFG->cookiesecure,
                        $CFG->cookiehttponly);

                    // Prefill more user information if new user.
                    if (!empty($newUser)) {
                        $newUser->id = $user->id;
                        $DB->update_record('user', $newUser);
                        $user = (object)array_merge((array)$user, (array)$newUser);
                    }

                    complete_user_login($user);

                    // Let's save/update the access token for this user.
                    $canSaveAccessToken = get_config('auth/googleoauth2', 'saveaccesstoken');
                    if (!empty($canSaveAccessToken)) {
                        $existingAccessToken = $DB->get_record('auth_googleoauth2_user_idps',
                            array('userid' => $user->id, 'provider' => $authProvider));
                        if (empty($existingAccessToken)) {
                            $accessTokenRow = new stdClass();
                            $accessTokenRow->userid = $user->id;
                            switch ($authProvider) {
                                case 'battlenet':
                                    $accessTokenRow->provideruserid = $userDetails->id;
                                    break;
                                default:
                                    $accessTokenRow->provideruserid = $userDetails->uid;
                                    break;
                            }

                            $accessTokenRow->provider = $authProvider;
                            $accessTokenRow->accesstoken = $accessToken;
                            $accessTokenRow->refreshtoken = $refreshToken;
                            $accessTokenRow->expires = $tokenExpires;

                            $DB->insert_record('auth_googleoauth2_user_idps', $accessTokenRow);

                        } else {
                            $existingAccessToken->accesstoken = $accessToken;
                            $DB->update_record('auth_googleoauth2_user_idps', $existingAccessToken);
                        }
                    }

                    // Check if the user picture is the default and retrieve the provider picture.
                    if (empty($user->picture)) {
                        $profilePiCurl = '';
                        switch ($authProvider) {
                            case 'battlenet':
                                $profilePiCurl = $userDetails->portrait_url;
                                break;
                            case 'google':
                                $profilePiCurl = str_replace('?sz=50', '?sz=300', $userDetails->imageUrl);
                                break;
                            default:
                                if (!empty($userDetails->imageUrl)) {
                                    $profilePiCurl = $userDetails->imageUrl;
                                }
                                break;
                        }
                        if (!empty($profilePiCurl)) {
                            $this->set_profile_picture($user, $profilePiCurl);
                        }
                    }

                    // Create event for authenticated user.
                    $event = \auth_googleoauth2\event\user_loggedin::create(
                        array('context' => context_system::instance(),
                            'objectid' => $user->id, 'relateduserid' => $user->id,
                            'other' => array('accesstoken' => $accessToken)));
                    $event->trigger();

                    // Redirection.
                    if (user_not_fully_set_up($USER)) {
                        $urlTogo = $CFG->wwwroot . '/user/edit.php';
                        // We don't delete $SESSION->wantsurl yet, so we get there later.
                    } else if (isset($SESSION->wantsurl) && (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
                        $urlTogo = $SESSION->wantsurl;    // Because it's an address in this site.
                        unset($SESSION->wantsurl);
                    } else {
                        // No wantsurl stored or external - go to homepage.
                        $urlTogo = $CFG->wwwroot . '/';
                        unset($SESSION->wantsurl);
                    }

                    $loginRecord = array('userid' => $USER->id, 'time' => time(),
                        'auth' => 'googleoauth2', 'subtype' => $authProvider);
                    $DB->insert_record('auth_googleoauth2_logins', $loginRecord);

                    redirect($urlTogo);
                } else {
                    // Authenticate_user_login() failure, probably email registered by another auth plugin.
                    // Do a check to confirm this hypothesis.
                    $userExist = $DB->get_record('user', array('email' => $userEmail));
                    if (!empty($userExist) && $userExist->auth != 'googleoauth2') {
                        $a = new stdClass();
                        $a->loginpage = (string)new moodle_url(empty($CFG->alternateloginurl) ?
                            '/login/index.php' : $CFG->alternateloginurl);
                        $a->forgotpass = (string)new moodle_url('/login/forgot_password.php');
                        throw new moodle_exception('couldnotauthenticateuserlogin', 'auth_googleoauth2', '', $a);
                    } else {
                        throw new moodle_exception('couldnotauthenticate', 'auth_googleoauth2');
                    }
                }
            } else {
                throw new moodle_exception('couldnotgetgoogleaccesstoken', 'auth_googleoauth2');
            }
        } else {
            // If you are having issue with the display buttons option, add the button code directly in the theme login page.
            if (get_config('auth/googleoauth2', 'oauth2displaybuttons')
                // Check manual parameter that indicate that we are trying to log a manual user.
                // We can add more param check for others provider but at the end,
                // the best way may be to not use the oauth2displaybuttons option and
                // add the button code directly in the theme login page.
                && empty($_POST['username'])
                && empty($_POST['password'])
            ) {
                // Display the button on the login page.
                require_once($CFG->dirroot . '/auth/googleoauth2/lib.php');

                // Insert the html code below the login field.
                // Code/Solution from Elcentra plugin: https://moodle.org/plugins/view/auth_elcentra.
                global $PAGE, $CFG;
                $PAGE->requires->jquery();
                $content = str_replace(array("\n", "\r"), array("\\\n", "\\\r"), auth_googleoauth2_display_buttons(false));
                $PAGE->requires->css('/auth/googleoauth2/style.css');
                $PAGE->requires->js_init_code("buttonsCodeOauth2 = '$content';");
                $PAGE->requires->js(new moodle_url($CFG->wwwroot . "/auth/googleoauth2/script.js"));
            }
        }
    }

    /**
     * Perform this function pre logout moodle
     */
    public function prelogout_hook(){

        $sid = $_SESSION['SID'];
        $accessToken = $_SESSION['ACCESSTOKEN'];
        if(!empty($sid) && !empty($accessToken)){

            global $CFG;
            $logoutUrl = $CFG->logoutUrl . $sid;

            $ch = curl_init($logoutUrl);
            $authorization = "Authorization: Bearer " . $accessToken;
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json' , $authorization ));
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
            $result = curl_exec($ch);
            curl_close($ch);
            if($result == "No token or token parsing error"){
                throw new moodle_exception( $result, 'auth_googleoauth2');
            }
        }
    }

    /**
     * Add revokeToken to cache
     */
    function addRevokeToken($revokeToken)
    {
        global $CFG;
        $payload = $this -> verifyAndDecodeToken($revokeToken);

        if ($CFG->issVerify == $payload->iss && $CFG->scopes == $payload->scp && time() < $payload->exp ){
            $cacheFile = $CFG->dirroot . '/auth/googleoauth2/cache/revokeToken/' . sha1($revokeToken) . '.html';
            file_put_contents($cacheFile,sha1($revokeToken));
        }
        exit();
    }
    
    /**
     * Retrieve the profile picture and save it in moodle.
     */
    private function set_profile_picture($user, $profilePiCurl)
    {
        global $CFG, $DB;

        require_once($CFG->libdir . '/filelib.php');
        require_once($CFG->libdir . '/gdlib.php');
        $imagefilename = $CFG->tempdir . '/googleoauth2-portrait-' . $user->id;
        $imagecontents = download_file_content($profilePiCurl);
        file_put_contents($imagefilename, $imagecontents);
        if ($newrev = process_new_icon(context_user::instance($user->id),
            'user', 'icon', 0, $imagefilename)
        ) {
            $DB->set_field('user', 'picture', $newrev, array('id' => $user->id));
        }
        unlink($imagefilename);
    }


    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * TODO: as print_auth_lock_options() core function displays an old-fashion HTML table, I didn't bother writing
     * some proper Moodle code. This code is similar to other auth plugins (04/09/11)
     */
    public function config_form($config, $err, $userfields)
    {
        global $OUTPUT, $CFG;

        echo '<div class="alert alert-success"  role="alert">' . get_string('supportmaintenance', 'auth_googleoauth2') . '</div>';


        // TODO: replace this table html ugliness by some nice bootstrap html code.
        echo '<table cellspacing="0" cellpadding="5" border="0">
            <tr>
               <td colspan="3">
                    <h2 class="main">';

        print_string('auth_googlesettings', 'auth_googleoauth2');

        $providers = provider_list();

        foreach ($providers as $providername) {

            $clientidname = $providername . 'clientid';
            $clientsecretname = $providername . 'clientsecret';

            // Set to defaults if undefined.
            if (!isset($config->{$clientidname})) {
                $config->{$clientidname} = '';
            }
            if (!isset($config->{$clientsecretname})) {
                $config->{$clientsecretname} = '';
            }

            // Client id.

            echo '</h2>
               </td>
            </tr>
            <tr  style="vertical-align: top;">
                <td align="right"><label for="' . $clientidname . '">';

            print_string('auth_' . $clientidname . '_key', 'auth_googleoauth2');

            echo '</label></td><td>';

            echo html_writer::empty_tag('input',
                array('type' => 'text', 'id' => $clientidname, 'name' => $clientidname,
                    'class' => $clientidname, 'value' => $config->{$clientidname}));

            if (isset($err[$clientidname])) {
                echo $OUTPUT->error_text($err[$clientidname]);
            }

            echo '</td><td>';
            $parse = parse_url($CFG->wwwroot);
            print_string('auth_' . $clientidname, 'auth_googleoauth2',
                array('jsorigins' => $parse['scheme'] . '://' . $parse['host'], 'siteurl' => $CFG->httpswwwroot,
                    'domain' => $CFG->httpswwwroot,
                    'redirecturls' => $CFG->httpswwwroot . '/auth/googleoauth2/' . $providername . '_redirect.php',
                    'callbackurl' => $CFG->httpswwwroot . '/auth/googleoauth2/' . $providername . '_redirect.php',
                    'sitedomain' => $parse['host']));

            echo '</td></tr>';

            // Client secret.

            echo '<tr  style="vertical-align: top;">
                <td align="right"><label for="' . $clientsecretname . '">';

            print_string('auth_' . $clientsecretname . '_key', 'auth_googleoauth2');

            echo '</label></td><td>';

            echo html_writer::empty_tag('input',
                array('type' => 'text', 'id' => $clientsecretname, 'name' => $clientsecretname,
                    'class' => $clientsecretname, 'value' => $config->{$clientsecretname}));

            if (isset($err[$clientsecretname])) {
                echo $OUTPUT->error_text($err[$clientsecretname]);
            }

            echo '</td><td>';

            print_string('auth_' . $clientsecretname, 'auth_googleoauth2');

            echo '</td></tr>
            <tr style="min-height: 20px"><td>&nbsp;</td></tr>';
        }

        if (!isset($config->googleipinfodbkey)) {
            $config->googleipinfodbkey = '';
        }

        if (!isset($config->googleuserprefix)) {
            $config->googleuserprefix = 'social_user_';
        }

        if (!isset($config->oauth2displaybuttons)) {
            $config->oauth2displaybuttons = 1;
        }

        // IPinfoDB.

        echo '<tr>
                <td align="right"><label for="googleipinfodbkey">';

        print_string('auth_googleipinfodbkey_key', 'auth_googleoauth2');

        echo '</label></td><td>';

        echo html_writer::empty_tag('input',
            array('type' => 'text', 'id' => 'googleipinfodbkey', 'name' => 'googleipinfodbkey',
                'class' => 'googleipinfodbkey', 'value' => $config->googleipinfodbkey));

        if (isset($err["googleipinfodbkey"])) {
            echo $OUTPUT->error_text($err["googleipinfodbkey"]);
        }

        echo '</td><td>';

        print_string('auth_googleipinfodbkey', 'auth_googleoauth2', (object)array('website' => $CFG->wwwroot));

        echo '</td></tr>';

        // User prefix.

        echo '<tr>
                <td align="right"><label for="googleuserprefix">';

        print_string('auth_googleuserprefix_key', 'auth_googleoauth2');

        echo '</label></td><td>';

        echo html_writer::empty_tag('input',
            array('type' => 'text', 'id' => 'googleuserprefix', 'name' => 'googleuserprefix',
                'class' => 'googleuserprefix', 'value' => $config->googleuserprefix));

        if (isset($err["googleuserprefix"])) {
            echo $OUTPUT->error_text($err["googleuserprefix"]);
        }

        echo '</td><td>';

        print_string('auth_googleuserprefix', 'auth_googleoauth2');

        echo '</td></tr>';

        // Display buttons.

        echo '<tr>
                <td align="right"><label for="oauth2displaybuttons">';

        print_string('oauth2displaybuttons', 'auth_googleoauth2');

        echo '</label></td><td>';

        $checked = empty($config->oauth2displaybuttons) ? '' : 'checked';
        echo html_writer::checkbox('oauth2displaybuttons', 1, $checked, '',
            array('type' => 'checkbox', 'id' => 'oauth2displaybuttons', 'class' => 'oauth2displaybuttons'));

        if (isset($err["oauth2displaybuttons"])) {
            echo $OUTPUT->error_text($err["oauth2displaybuttons"]);
        }

        echo '</td><td>';

        $code = '<code>&lt;?php require_once($CFG-&gt;dirroot . \'/auth/googleoauth2/lib.php\');
                auth_googleoauth2_display_buttons(); ?&gt;</code>';
        print_string('oauth2displaybuttonshelp', 'auth_googleoauth2', $code);

        echo '</td></tr>';


        // Block field options.
        // Hidden email options - email must be set to: locked.
        echo html_writer::empty_tag('input', array('type' => 'hidden', 'value' => 'locked',
            'name' => 'lockconfig_field_lock_email'));

        // Display other field options.
        foreach ($userfields as $key => $userfield) {
            if ($userfield == 'email') {
                unset($userfields[$key]);
            }
        }
        print_auth_lock_options('googleoauth2', $userfields, get_string('auth_fieldlocks_help', 'auth'), false, false);

        echo '</table>';

        // Calculate how many login per providers.
        $providerstats = (object)$this->get_stats();
        $strothermoodle = get_string('othermoodle', 'auth_googleoauth2');
        $strstattitle = get_string('stattitle', 'auth_googleoauth2', $providerstats);
        echo '
            <center>
            <script type="text/javascript" src="https://www.google.com/jsapi"></script>
                <script type="text/javascript">
                  google.load("visualization", "1", {packages:["corechart"]});
                  google.setOnLoadCallback(drawChart);
                  function drawChart() {

                    var data = google.visualization.arrayToDataTable([
                      [\'Provider\', \'Login total\'],
                      [\'Google\', ' . $providerstats->google . '],
                      [\'Facebook\', ' . $providerstats->facebook . ' ],
                      [\'Vp\', ' . $providerstats->vp . ' ],
                      [\'Github\',  ' . $providerstats->github . ' ],
                      [\'Linkedin\', ' . $providerstats->linkedin . ' ],
                      [\'Microsoft\', ' . $providerstats->microsoft . ' ],
                      [\'Dropbox\', ' . $providerstats->dropbox . ' ],
                      [\'VK\', ' . $providerstats->vk . ' ],
                      [\'Battle.net\', ' . $providerstats->battlenet . ' ],
                      [\'' . $strothermoodle . '\',    ' . $providerstats->moodle . ' ]
                    ]);

                    var options = {
                      title: \'' . $strstattitle . '\',
                      is3D: true,
                      slices: {
                        0: { color: \'#D50F25\' },
                        1: { color: \'#3b5998\' },
                        2: { color: \'#eee\', fontcolor: \'black\'},
                        3: { color: \'#007bb6\'},
                        4: { color: \'#7cbb00\'},
                        5: { color: \'#007ee5\'},
                        6: { color: \'#45668e\'},
                        7: { color: \'#00B4FF\'},
                        8: { color: \'#ee7600\'}
                      }
                    };

                    var chart = new google.visualization.PieChart(document.getElementById(\'piechart\'));

                    chart.draw(data, options);
                  }
                </script>
             <div id="piechart" style="width: 900px; height: 500px;"></div>
            </center>
        ';
    }

    /**
     * Retrieve the login provider stats.
     */
    public function get_stats($periodindays = 60)
    {
        global $DB;

        // Retrieve the logins.
        $sql = 'time > :time';
        $logins = $DB->get_records_select('auth_googleoauth2_logins', $sql,
            array('time' => strtotime('-' . $periodindays . ' days', time())));

        // Retrieve the moodle auth stats.
        $loginstats = array('google' => 0,
            'facebook' => 0,
            'vp' => 0,
            'github' => 0,
            'linkedin' => 0,
            'microsoft' => 0,
            'dropbox' => 0,
            'vk' => 0,
            'battlenet' => 0,
            'moodle' => 0,
            'periodindays' => $periodindays);

        // Retrieve the provider stats.
        foreach ($logins as $login) {
            if ($login->auth !== 'googleoauth2') {
                $loginstats['moodle'] += 1;
            } else {
                $loginstats[$login->subtype] += 1;
            }
        }


        return $loginstats;
    }


    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    public function process_config($config)
    {
        // Set to defaults if undefined.

        $providers = provider_list();

        foreach ($providers as $providername) {
            $clientidname = $providername . 'clientid';
            $clientsecretname = $providername . 'clientsecret';

            // Set to defaults if undefined.
            if (!isset($config->{$clientidname})) {
                $config->{$clientidname} = '';
            }
            if (!isset($config->{$clientsecretname})) {
                $config->{$clientsecretname} = '';
            }

            // Save settings.
            set_config($clientidname, $config->{$clientidname}, 'auth/googleoauth2');
            set_config($clientsecretname, $config->{$clientsecretname}, 'auth/googleoauth2');
        }

        if (!isset ($config->googleuserprefix)) {
            $config->googleuserprefix = 'social_user_';
        }
        if (!isset ($config->oauth2displaybuttons)) {
            $config->oauth2displaybuttons = 0;
        }

        set_config('googleipinfodbkey', $config->googleipinfodbkey, 'auth/googleoauth2');
        set_config('googleuserprefix', core_text::strtolower($config->googleuserprefix), 'auth/googleoauth2');
        set_config('oauth2displaybuttons', $config->oauth2displaybuttons, 'auth/googleoauth2');

        return true;
    }

    /**
     * Called when the user record is updated.
     *
     * We check there is no hack-attempt by a user to change his/her email address
     *
     * @param mixed $olduser Userobject before modifications    (without system magic quotes)
     * @param mixed $newUser Userobject new modified userobject (without system magic quotes)
     * @return boolean result
     *
     */
    public function user_update($olduser, $newUser)
    {
        if ($olduser->email != $newUser->email) {
            return false;
        }
        return true;
    }
}
