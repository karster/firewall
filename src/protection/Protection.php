<?php

namespace karster\security\protection;

use karster\security\GlobalVariable;

class Protection
{
    /**
     * @var mixed
     */
    protected $rules;

    /**
     * @var GlobalVariable
     */
    public $globalVariable;

    /**
     * Protection constructor.
     * @param array $rules
     */
    public function __construct($rules = [])
    {
        $this->setRules($rules);
        $this->globalVariable = new GlobalVariable();
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

    protected function loadRulesFromFile($file)
    {
        return json_decode(file_get_contents($file), true);
    }
}