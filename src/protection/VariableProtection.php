<?php

namespace karster\security\protection;

class VariableProtection extends Protection
{
    protected function checkVariables($variable)
    {
        $runProtection = false;
        $rules = $this->getRules();
        if (!empty($variable) && !empty($rules)) {
            foreach ($variable as &$value) {
                foreach ($rules as $rule) {
                    if (preg_match("/$rule/", $value)) {
                        $runProtection = true;
                        break;
                    }
                }

                if ($runProtection) {
                    break;
                }
            }
        }

        return $runProtection;
    }
}
