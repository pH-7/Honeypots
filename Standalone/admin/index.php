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
 * This page is a fake admin login page of site.
 * Your real login page it just another URL (e.g. http://your-site.com/_my-secret-admin-page/).
 */


require '../../_inc/Sniff.class.php'; // Include the class.

$bErr = false; // Initialize the error variable.

if(isset($_POST['usr'], $_POST['pwd']))
{
    sleep(6); // Security against brute-force attack and this will irritate the hacker...
    $bErr = true; // Display an error message indicating that the login is incorrect.
    new Sniff($_POST['usr'], $_POST['pwd']); // Class declaration with initialization values connection.
}

/**
 * Checks if the IP address is banned.
 */
if(Sniff::isIpBlock())
{   /**
     * Redirect to the index page.
     * Instead, you can display a message indicating that the user has been banned or another redirection.
     */
    header('Location: ../');
    exit;
}

?>
<!DOCTYPE html>
<html lang="en-US">
  <head>
      <meta charset="utf-8" />
      <title>Honeypot | Standalone example</title>
      <meta name="description" content="This is a simple PHP standalone example of honeypot for pirat" />
      <meta name="keywords" content="honeypot, example, PHP, security" />
      <meta name="author" content="Pierre-Henry Soria" />
      <link rel="stylesheet" href="./../static/css/general.css" />
      <!-- Your Analytics Code here (e.g. Google Analytics: http://www.google.com/analytics/, Piwik: http://piwik.org) -->
  </head>
  <body>
      <div id="container">

          <header>
              <h1>Honeypot Example</h1>
          </header>

          <h2 class="blue">Admin Panel</h2>
          <form class="center" action="index.php" method="post">
            <fieldset>
              <legend>Login</legend>
              <?php if($bErr) echo '<p class="center warning_block">Your username or password was incorrect. Please try again.</p>'; ?>
              <label for="usr">Username:</label>
              <input type="text" name="usr" id="usr" value="admin" onfocus="if('admin' == this.value) this.value='';" onblur="if('' == this.value) this.value = 'admin';" required="required" />
              <label for="pwd">Password:</label>
              <input type="password" name="pwd" id="pwd" required="required" />
              <div class="center"><button type="submit" name="submit">Login</button></div>
            </fieldset>
          </form>

          <footer>
              <p>By <strong><a href="http://ph-7.github.com">pH7</a></strong> &copy; 2012.</p>
          </footer>

      </div>
  </body>
</html>
