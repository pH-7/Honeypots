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
 * Sniffer Honeypot Class.
 */
class Sniff
{

    /**
     * Your informations here.
     */

    // TRUE = enable sending email to each someone tries to connect to admin login.
    const EMAIL_REPORT = true;

    // Email address where reports will be sent emails if Sniff::EMAIL_REPORT is TRUE.
    const EMAIL_ADDRESS = 'you@your-domain.com';


    /**
     * Settings of application.
     */

    // TRUE = Automatically banned all those who attempt to log into the admin.
    const AUTO_IP_BLOCK = true;

    // Path where will be stored log files.
    const LOG_PATH = '../../_data/logs/attackers/';

    // Path from the list of IP addresses that are banned from the site.
    const BAN_IP_FULL_PATH = '../../_data/bans/ip.txt';


    /**
     * Username entered in the login.
     *
     * @access private
     * @var string $_sUsername
     */
     private $_sUsername;

     /**
      * Password entered in the login.
      *
      * @access private
      * @access string $_sPassword
      */
     private $_sPassword;

    /**
     * IP address.
     *
     * @access private
     * @var string $_sIp
     */
    private $_sIp;

    /**
     * The informations contents.
     *
     * @access private
     * @var string $_sContents
     */
    private $_sContents;

    /**
     * Constructor.
     *
     * @access public
     * @param string $sUsername The Username of the Admin Login.
     */
    public function __construct($sUsername, $sPassword)
    {   // Initializes login variables.
        $this->_sUsername = $sUsername;
        $this->_sPassword = $sPassword;

        // Creates the log message and adds it to the list of logs.
        $this->setLogMsg()->writeFile();

        // Sends the email report.
        if(self::EMAIL_REPORT) $this->sendMessage();

        // Blocks IP address.
        if(self::AUTO_IP_BLOCK) $this->blockIp();
    }

    /**
     * Check if the IP address is banned.
     *
     * @access public
     * @return boolean Returns true if the ip is banned, otherwise returns false.
     */
    public static function isIpBlock()
    {
        if(is_file(self::BAN_IP_FULL_PATH))
        {
            $aIpBans = file(self::BAN_IP_FULL_PATH);

            foreach($aIpBans as $sIp)
            {
                $sIp = trim($sIp);
                if(0 == strcmp(self::getIp(), $sIp)) return true;
            }
        }

        return false;
    }

    /**
     * Return the IP address of a client.
     *
     * @access public
     * @return string
     */
    public static function getIp()
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
        {
            $sIp = $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
        elseif (!empty($_SERVER['HTTP_CLIENT_IP']))
        {
            $sIp = $_SERVER['HTTP_CLIENT_IP'];
        }
        else
        {
            $sIp = $_SERVER['REMOTE_ADDR'];
        }

        return preg_match('/^[a-z0-9:.]{7,}$/', $sIp) ? $sIp : '0.0.0.0';
    }

    /**
     * Build the log message.
     *
     * @access protected
     * @return this object
     */
     protected function setLogMsg()
     {
        $sReferer = (!empty($_SERVER['HTTP_REFERER'])) ? $_SERVER['HTTP_REFERER'] : 'NO HTTP REFERER';
        $sAgent = (!empty($_SERVER['HTTP_USER_AGENT'])) ? $_SERVER['HTTP_USER_AGENT'] : 'NO USER AGENT';
        $sQuery = (!empty($_SERVER['QUERY_STRING'])) ? $_SERVER['QUERY_STRING'] : 'NO QUERY STRING';

        $this->_sIp = self::getIp();

        $this->_sContents =
        'Date: ' . date('Y/m/d') . "\n" .
        'IP: ' . $this->_sIp . "\n" .
        'QUERY: ' . $sQuery . "\n" .
        'Agent: ' . $sAgent . "\n" .
        'Referer: ' . $sReferer . "\n" .
        'LOGIN - Username: ' . $this->_sUsername . ' - Password: ' . $this->_sPassword . "\n\n\n";

        return $this;
     }

    /**
     * Write a log file with the hacher informations.
     *
     * @access protected
     * @return this object
     */
    protected function writeFile()
    {
        $sFullPath =  self::LOG_PATH . $this->_sIp . '.log';
        file_put_contents($sFullPath, $this->_sContents, FILE_APPEND);
        return $this;
    }

    /**
     * Blocking IP address.
     *
     * @access protected
     * @return this object
     */
    protected function blockIp()
    {
        file_put_contents(self::BAN_IP_FULL_PATH, $this->_sIp . "\n", FILE_APPEND);
        return $this;
    }

    /**
     * Send an email.
     *
     * @access protected
     * @return this object
     */
    protected function sendMessage()
    {
        $sHeaders = "From: \"{$_SERVER['HTTP_HOST']}\" <{$_SERVER['SERVER_ADMIN']}>\r\n";
        mail(self::EMAIL_ADDRESS, 'Reporting of the Fake Admin Honeypot', $this->_sContents, $sHeaders);

        return $this;
    }

}
