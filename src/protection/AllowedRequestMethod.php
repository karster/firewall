<?php

namespace karster\security\protection;

class AllowedRequestMethod extends Protection implements ProtectionInterface
{
    /**
     * @param array $rules
     * @return $this
     */
    public function setRules($rules)
    {
        if (!empty($rules) && is_array($rules)) {
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
        $rules = $this->getRules();
        $method = $this->getRequestMethod();

        if (!in_array($method, $rules)) {
            $runProtection = true;
        }

        return $runProtection;
    }
}
