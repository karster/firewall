<?php

namespace karster\security\protection;


class Rule
{
    /**
     * @var mixed
     */
    protected $rules;

    /**
     * Rule constructor.
     * @param array $rules
     */
    public function __construct($rules = [])
    {
        $this->setRules($rules);
    }

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
     * @return mixed
     */
    public function getRules()
    {
        return $this->rules;
    }

    public function setRules($rules)
    {
        $this->rules = $rules;

        return $this;
    }

    protected function loadRulesFromFile($file)
    {
        return json_decode(file_get_contents($file), true);
    }

    /**
     * @return string
     */
    protected function getQueryString()
    {
        return strtolower(str_replace('%09', '%20', $this->getGlobalVariable('QUERY_STRING')));
    }

    /**
     * @return bool|string
     */
    protected function getReferer()
    {
        $referer = $this->getGlobalVariable('HTTP_REFERER');

        return !empty($referer) ? $referer : false;
    }

    /**
     * @return string
     */
    protected function getIp()
    {
        $indices = ['HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];

        foreach ($indices as $index) {
            $ip = $this->getGlobalVariable($index);
            if (!empty($ip)) {
                return $ip;
            }
        }
    }

    /**
     * @return string
     */
    protected function getUserAgent()
    {
        $user_agent = $this->getGlobalVariable('HTTP_USER_AGENT');

        return !empty($user_agent) ? $user_agent : false;
    }

    /**
     * @return string
     */
    protected function getRequestMethod()
    {
        return strtoupper($this->getGlobalVariable('REQUEST_METHOD'));
    }

}