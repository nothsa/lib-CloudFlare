<?php
/**
 * Cloudflare Client API Interface Library
 */

/**
 * Cloudflare
 *
 * @category      APIs/Cloudflare
 * @author        Ashton Cummings
 * @link          https://github.com/nothsa/lib-CloudFlare
 * @link          [FORKED FROM] https://github.com/circuitbomb/Cloudflare-for-CodeIgniter
 */

class Cloudflare
{
    private $_api_url = "https://www.cloudflare.com/api_json.html?"; //Cloudflare API URL
    private $_log_path = NULL;                                       //Path to log requests with trailing slash
    private $_token = "your-cloudflare-token";                       //Cloudflare API key
    private $_email = "your-cloudflare-account-email-address";       //Associated Email address
    private $_default_zone = NULL;                                   //Default Zone (e.g. example.com)

    private $_params;

    /**
     * @param string $token The token used to access the API (defaults to the token specified in the library)
     * @param string $email The email address used to access the API (defaults to the email address specified in the library)
     * @param string $default_zone The default zone to use if one is not specified when requesting a call
    */
    public function __construct($token=NULL, $email=NULL, $default_zone=NULL)
    {
        if(!is_null($token)) { $this->_token = $token; }
        if(!is_null($email)) { $this->_email = $email; }
        if(!is_null($default_zone)) { $this->_default_zone = $default_zone; }
        $this->_params = array('tkn' => $this->_token, 'email' => $this->_email);
    }

    /**
     * Set a parameter for the API request
     * @param mixed $key The key to set in the parameters array
     * @param mixed $value The value to set in the parameters array
    */
    private function _set_param($key, $value) { $this->_params[$key] = $value; }

    /**
    * Makes POST request via cURL to Cloudflare API. Wites to log file if log folder is specified in $this->_log_path.
    * At time of writing, Cloudflare Client API is rate limited to 1200 per 5 mins.
    * @param array $params API request parameters
    * @return string CloudFlare JSON return
    */
    private function _request($params=NULL)
    {
        if(is_null($params)) { $params = $this->_params; }

        if(array_key_exists('z', $params) && is_null($params['z']))
        if(!isset($params['z']))
            $params['z'] = $this->_default_zone;

        $init = curl_init();

        if(!is_null($this->_log_path))
            $fp = fopen($this->_log_path . "cloudflare_".$params['a']."-".date("Y-m-d").".txt", "a");

        curl_setopt($init, CURLOPT_URL, $this->_api_url);
        curl_setopt($init, CURLOPT_FORBID_REUSE, TRUE);
        curl_setopt($init, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($init, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($init, CURLOPT_POST, 1);
        curl_setopt($init, CURLOPT_POSTFIELDS, $params);

        $exec  = curl_exec($init);
        $error = curl_error($init);
        $code  = curl_getinfo($init, CURLINFO_HTTP_CODE);

        if($code != 200)
            $exec = json_encode(array("error" => $error));

        if(!is_null($this->_log_path))
        {
            fwrite($fp, $exec);
            fclose($fp);
        }
        curl_close($init);

        return $exec;
    }

    /**
    * Retrieve the current stats and settings for a particular domain.
    * This function can be used to get currently settings of values such as the security level.
    * @param int $interval The time interval for which to retrieve data
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    *
    * Time interval values, the latest data is from one day ago
    *    10 = Past 365 days
    *    20 = Past 30 days
    *    30 = Past 7 days
    *    40 = Past day
    *
    * These values are for Pro (or higher) accounts
    *    100 = 24 hours ago
    *    110 = 12 hours ago
    *    120 = 6 hours ago
    */
    public function get_stats($interval=40, $zone=NULL)
    {
        $this->_set_param('a', 'stats');
        $this->_set_param('z', $zone);
        $this->_set_param('interval', $interval);
        return $this->_request();
    }

    /**
    * Returns a list of all domains in a CloudFlare account, along with other data.
    * @return string CloudFlare JSON return
    */
    public function get_zones_all()
    {
        $this->_set_param('a', 'zone_load_multi');
        return $this->_request();
    }

    /**
    * Returns a list of all of the DNS records from a single domain
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    */
    public function get_DNS_records($zone=NULL)
    {
        $this->_set_param('a', 'rec_load_all');
        $this->_set_param('z', $zone);
        return $this->_request();
    }

    /*
    * Returns a list of active zones and their corresponding zone ids
    * @param string $zone The zone(s) to which the request applies (specify multiple zones in a comma-seperated list)
    * @return string CloudFlare JSON return
    */
    public function get_zones_active($zone=NULL)
    {
        $this->_set_param('a', 'zone_check');
        $this->_set_param('z', $zone);
        return $this->_request();
    }

    /*
    * Returns a list of IP addresses which hit your site classified by type.
    * @param int $hours Past number of hours to query. Default is 24, maximum is 48.
    * @param string $class Restrict the result set to a given class (details in notes)
    * @param int $geo Whether or not to add longitude and latitude information to response (0 or 1)
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    *
    * Class, optional restrictions
    *    n = none
    *    r = regular
    *    s = crawler
    *    t = threat
    */
    public function get_IPs_recent($hours=24, $class="r", $geo=0, $zone=NULL)
    {
        $this->_set_param('a', 'zone_ips');
        $this->_set_param('hours', $hours);
        $this->_set_param('z', $zone);

        if($class == "r" || $class == "s" || $class == "t") 
            $this->_set_param('class', $class);

        if($geo == 1)
            $this->_set_param('geo', $geo);

        return $this->_request();

    }

    /*
    * Returns the threat score for a given IP. 
    * Note that scores are on a logarithmic scale, where a higher score indicates a higher threat.
    * @param string $ip_address The IP address for the request
    * @return string CloudFlare JSON return
    */
    public function get_IPs_score($ip_address)
    {
        $this->_set_param('a', 'ip_lkup');
        $this->_set_param('ip', $ip_address);
        return $this->_request();
    }

    /*
    * Sets the Basic Security Level to I'M UNDER ATTACK! / HIGH / MEDIUM / LOW / ESSENTIALLY OFF.
    * @param string $level Security level to set the zone to (details in notes)
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    *
    * Security Levels
    *    help - I'm under attack
    *    high - High
    *    med  - Medium
    *    low  - Low
    *    eoff - Essentially Off
    */
    public function mod_security_level($level="med", $zone=NULL)
    {
        $this->_set_param('a', 'sec_lvl');
        $this->_set_param('z', $zone);
        $this->_set_param('v', $level);
        return $this->_request();
    }

    /*
    * Sets the Caching Level to Aggressive or Basic.
    * @param string $level Cache level to set the zone to (details in notes)
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    *
    * Cache Levels
    *    agg - Aggressive
    *    basic - Basic
    */
    public function mod_cache_level($level="basic", $zone=NULL)
    {
        $this->_set_param('a', 'cache_lvl');
        $this->_set_param('z', $zone);
        return $this->_request();
    }

    /*
    * Toggles "Development Mode" on or off for a specific domain. When Development Mode is on the cache is bypassed. 
    * Development mode remains on for 3 hours or until when it is toggled back off.
    * @param int $switch Whether to switch Dev Mode on or off (0 or 1)
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    */
    public function mod_dev_mode($switch=0, $zone=NULL)
    {
        $this->_set_param('a', 'devmode');
        $this->_set_param('z', $zone);
        $this->_set_param('v', $switch);
        return $this->_request();
    }

    /*
    * Purge all of the cache from CloudFlare for the specified domain.
    * It may take a while for the cache to rebuild and optimum performance to be achieved, so this function should be used sparingly.
    * If you wish to purge the cache for a single file (much faster), use mod_purge_cache_file()
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    */
    public function mod_purge_cache($zone=NULL)
    {
        $this->_set_param('a', 'fpurge_ts');
        $this->_set_param('z', $zone);
        $this->_set_param('v', 1);
        return $this->_request();
    }

    /*
    * Purge the cache for a single file from CloudFlare for the specified domain.
    * @param string $file_url The URL of the file to remove from cache
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    */
    public function mod_purge_cache_file($file_url, $zone=NULL)
    {
        $this->_set_param('a', 'zone_file_purge');
        $this->_set_param('z', $zone);
        $this->_set_param('url', $file_url);
        return $this->_request();
    }

    /*
    * Tells CloudFlare to take a new image of your site.
    * @param int $zone_id The ID of the zone to re-image
    * @return string CloudFlare JSON return
    */
    public function mod_zone_grab($zone_id=NULL)
    {
        if(is_null($zone_id))
        {
            // If no zone ID set, get the first active zone ID
            $json = $this->get_zones_active();
            $array = json_decode($json, TRUE);

            $zone_id = $array[0][0][0];    
        }

        $this->_set_param('a', 'zone_grab');
        $this->_set_param('zid', $zone_id);
        return $this->_request();
    }

    /*
    * Ban an IP Address from your domains
    * @param string $ip_address The IP address to blacklist
    * @return string CloudFlare JSON return
    */
    public function mod_blacklist_IP($ip_address)
    {
        $this->_set_param('a', 'ban');
        $this->_set_param('key', $ip_address);
        return $this->_request();
    }

    /*
    * Allow an IP Address on your domains
    * @param string $ip_address The IP address to whitelist
    * @return string CloudFlare JSON return
    */
    public function mod_whitelist_IP($ip_address)
    {
        $this->_set_param('a', 'wl');
        $this->_set_param('key', $ip_address);
        return $this->_request();    
    }

    /*
    * Removes an IP address from the blacklist and whitelist (i.e. the IP will not receive special treatment)
    * @param string $ip_address The IP address to remove from lists
    * @return string CloudFlare JSON return
    */
    public function mod_unlist_IP($ip_address)
    {
        $this->_set_param('a', 'nul');
        $this->_set_param('key', $ip_address);
        return $this->_request();    
    }

    /*
    * Toggles IPv6 support on/off
    * @param int $switch Whether to switch IPv6 support on or off (0 or 1)
    * @param string $zone The zone to which the request applies
    * @return string CloudFlare JSON return
    */
    public function mod_IPv6_toggle($switch=0, $zone=NULL)
    {
        $this->_set_param('a', 'ipv46');
        $this->_set_param('z', $zone);
        $this->_set_param('v', $switch);
        return $this->_request();
    }
}
