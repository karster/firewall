<?php

namespace karster\security\protection;

class AllowedGlobals extends Protection implements ProtectionInterface
{
    /**
     * @param array $rules
     * @return $this
     */
    public function setRules($rules)
    {
        if (!empty($rules)) {
            $rules = array_merge($rules, ['GLOBALS']);
            foreach ($rules as $rule) {
                $this->rules[] = strtoupper($rule);
            }
        }

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function protect()
    {
        $runProtection = false;
        if (isset($GLOBALS)) {
            $rules = $this->getRules();

            foreach ($GLOBALS as $key => $value) {
                if (!in_array($key, $rules)) {
                    unset($GLOBALS[$key]);
                    $runProtection = true;
                }
            }
        }

        return $runProtection;
    }
}
