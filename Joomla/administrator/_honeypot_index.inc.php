<?php
/**
 * @category       Honeypot
 * @package        Security
 * @author         Pierre-Henry Soria <ph7software@gmail.com>
 * @copyright      (c) 2012, Pierre-Henry Soria. All Rights Reserved.
 * @license        CC-BY License - http://creativecommons.org/licenses/by/3.0/
 * @version        1.0.0
 */


/**
 * Architecture and design reproduced of Joomla version 2.5.6
 */
defined('IS_INDEX') or die; // Security check

session_start();

/**
 * Generate a random token name field of the login form.
 */
if(empty($_SESSION['login_token']))
    $_SESSION['login_token'] = md5(uniqid(mt_rand(), true));

/**
 * Gets the root URL.
 * It is useful to get the URL to reproduce exactly the same source code as the original Joomla administration.
 *
 * @return string
 */
function get_url()
{
    // URL Association for SSL and Protocol Compatibility
    $sHttp = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS'] == 'on')) ? 'https://' : 'http://';

    return $sHttp . $_SERVER['HTTP_HOST'] . dirname(dirname(htmlspecialchars($_SERVER['PHP_SELF'])));
}

/**
 * Gets the root relative URL.
 * It is useful to get the URL relative to reproduce exactly the same source code as the original Joomla administration.
 *
 * @return string
 */
function get_relative_url()
{
    return dirname(dirname(htmlspecialchars($_SERVER['PHP_SELF'])));
}

/**
 * This page is a fake admin login page of site.
 * Your real login page it just another URL (e.g. http://your-site.com/_my-secret-admin-page/).
 */
require '../../_inc/Sniff.class.php';

$bErr = false; // Default value

if(isset($_POST['username'], $_POST['passwd']))
{
    sleep(6); // Security against brute-force attack and this will irritate the hacker...
    $bErr = true;
    new Sniff($_POST['username'], $_POST['passwd']);
}

/**
 * Check if the IP address is banned.
 */
if(Sniff::isIpBlock())
{
    header('Location: ../'); // Go to index.
    exit;
}

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en-gb" lang="en-gb" dir="ltr" >
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8" />
  <meta name="generator" content="Joomla! - Open Source Content Management" />
  <title>Honeypot Joomla Example - Administration</title>
  <link href="<?php echo get_relative_url() ?>/administrator/templates/bluestork/favicon.ico" rel="shortcut icon" type="image/vnd.microsoft.icon" />
  <link rel="stylesheet" href="templates/system/css/system.css" type="text/css" />
  <link rel="stylesheet" href="templates/bluestork/css/template.css" type="text/css" />
  <style type="text/css">
html { display:none }
  </style>
  <script src="<?php echo get_relative_url() ?>/media/system/js/mootools-core.js" type="text/javascript"></script>
  <script src="<?php echo get_relative_url() ?>/media/system/js/core.js" type="text/javascript"></script>
  <script type="text/javascript">
function keepAlive() {    var myAjax = new Request({method: "get", url: "index.php"}).send();} window.addEvent("domready", function(){ keepAlive.periodical(840000); });
window.addEvent('domready', function () {if (top == self) {document.documentElement.style.display = 'block'; } else {top.location = self.location; }});
  </script>


<!--[if IE 7]>
<link href="templates/bluestork/css/ie7.css" rel="stylesheet" type="text/css" />
<![endif]-->

<script type="text/javascript">
    window.addEvent('domready', function () {
        document.getElementById('form-login').username.select();
        document.getElementById('form-login').username.focus();
    });
</script>
</head>
<body>
    <div id="border-top" class="h_blue">
        <span class="title"><a href="index.php">Administration</a></span>
    </div>
    <div id="content-box">
            <div id="element-box" class="login">
                <div class="m wbg">
                    <h1>Joomla! Administration Login</h1>

<div id="system-message-container">
</div>
                            <div id="section-box">
            <div class="m">
                <form action="<?php echo get_relative_url() ?>/administrator/index.php" method="post" id="form-login">
    <fieldset class="loginform">

                <label id="mod-login-username-lbl" for="mod-login-username">User Name</label>
                <input name="username" id="mod-login-username" type="text" class="inputbox" size="15" />

                <label id="mod-login-password-lbl" for="mod-login-password">Password</label>
                <input name="passwd" id="mod-login-password" type="password" class="inputbox" size="15" />

                <label id="mod-login-language-lbl" for="lang">Language</label>
                <select id="lang" name="lang"  class="inputbox">
    <option value="" selected="selected">Default</option>
    <option value="en-GB">English (United Kingdom)</option>
</select>

                <div class="button-holder">
                    <div class="button1">
                        <div class="next">
                            <a href="#" onclick="document.getElementById('form-login').submit();">
                                Log in</a>
                        </div>
                    </div>
                </div>

        <div class="clr"></div>
        <input type="submit" class="hidebtn" value="Log in" />
        <input type="hidden" name="option" value="com_login" />
        <input type="hidden" name="task" value="login" />
        <input type="hidden" name="return" value="aW5kZXgucGhw" />
        <input type="hidden" name="<?php echo $_SESSION['login_token'] ?>" value="1" />    </fieldset>
</form>
                <div class="clr"></div>
            </div>
        </div>

                    <p>Use a valid username and password to gain access to the administrator backend.</p>
                    <p><a href="<?php echo get_url() ?>">Go to site home page.</a></p>
                    <div id="lock"></div>
                </div>
            </div>
            <noscript>
                Warning! JavaScript must be enabled for proper operation of the Administrator backend.            </noscript>
    </div>
    <div id="footer">
        <p class="copyright">
            <a href="http://www.joomla.org">Joomla!&#174;</a> is free software released under the <a href="http://www.gnu.org/licenses/gpl-2.0.html">GNU General Public License</a>.        </p>
    </div>
</body>
</html>
