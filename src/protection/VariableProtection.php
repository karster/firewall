<?php

namespace karster\security\protection;


class VariableProtection extends Protection
{
    protected function checkVariables($variable)
    {
        $runProtection = false;
        if (!empty($variable)) {
            $rules = $this->getRules();
            foreach($variable as &$value) {
                $count = 0;
                str_replace($rules, '*', $value, $count);
                if ($count > 0) {
                    unset($value);
                    $runProtection = true;
                }
            }
        }

        return $runProtection;
    }
}