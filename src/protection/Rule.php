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
    protected function getGlobalVariable($variable_name)
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
}