<?php

namespace karster\security;

/**
 * Class GlobalVariableTrait
 * @package karster\security
 */
trait GlobalVariableTrait
{
    /**
     * @access protected
     * @param $variable_name
     * @return bool|string
     */
    private function getGlobalVariable($variable_name)
    {
        if (isset($_SERVER[$variable_name])) {
            return strip_tags($_SERVER[$variable_name]);
        }

        if (isset($_ENV[$variable_name])) {
            return strip_tags($_ENV[$variable_name]);
        }

        if (getenv($variable_name)) {
            return strip_tags(getenv($variable_name));
        }

        if (function_exists('apache_getenv') && apache_getenv($variable_name, true)) {
            return strip_tags(apache_getenv($variable_name, true));
        }

        return false;
    }

    /**
     * @return string
     */
    public function getQueryString()
    {
        return strtolower(str_replace('%09', '%20', $this->getGlobalVariable('QUERY_STRING')));
    }

    /**
     * @return bool|string
     */
    public function getReferer()
    {
        return $this->getGlobalVariable('HTTP_REFERER');
    }

    /**
     * @return string
     */
    public function getIp()
    {
        $indices = ['REMOTE_ADDR', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR'];

        foreach ($indices as $index) {
            $ip = $this->getGlobalVariable($index);
            if (!empty($ip)) {
                return $ip;
            }
        }

        return false;
    }

    /**
     * @return string
     */
    public function getUserAgent()
    {
        return $this->getGlobalVariable('HTTP_USER_AGENT');
    }

    /**
     * @return string
     */
    public function getRequestMethod()
    {
        return strtoupper($this->getGlobalVariable('REQUEST_METHOD'));
    }

    /**
     * @return string
     */
    public function getRequestUri()
    {
        return $this->getGlobalVariable('REQUEST_URI');
    }
}
