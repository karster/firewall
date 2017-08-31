<?php

namespace karster\security\protection;

use karster\security\GlobalVariableTrait;

abstract class Protection
{
    use GlobalVariableTrait;
    /**
     * @var mixed
     */
    protected $rules;

    /**
     * Protection constructor.
     * @param array $rules
     */
    public function __construct($rules = [])
    {
        $this->setRules($rules);
    }

    /**
     * @return mixed
     */
    public function getRules()
    {
        return $this->rules;
    }

    /**
     * @param $rules
     * @return $this
     */
    public function setRules($rules)
    {
        $this->rules = $rules;

        return $this;
    }

    /**
     * @param string $file
     * @return mixed
     */
    protected function loadRulesFromFile($file)
    {
        return json_decode(file_get_contents($file), true);
    }

    /**
     * @access public
     * @return bool
     */
    abstract public function protect();
}
