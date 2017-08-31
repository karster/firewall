<?php

namespace karster\security\protection;

abstract class VariableProtection extends Protection
{
    protected function checkVariables($variable)
    {
        $runProtection = false;
        $rules = $this->getRules();
        if (!empty($variable) && !empty($rules)) {
            foreach ($rules as $rule) {
                if (preg_grep("#$rule#", $variable)) {
                    $runProtection = true;
                    break;
                }
            }
        }

        return $runProtection;
    }
}
