<?php

namespace karster\security\protection;

class UrlProtection extends Protection implements ProtectionInterface
{
    /**
     * @param array $rules
     * @return $this
     */
    public function setRules($rules)
    {
        if (!empty($rules)) {
            foreach ($rules as $rule) {
                $this->rules[] = strtolower($rule);
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
        $query_string = $this->getQueryString();
        $rules = $this->getRules();

        if (!empty($query_string) && !empty($rules)) {
            foreach ($rules as $rule) {
                if (preg_match("#$rule#", rawurldecode($query_string))) {
                    $runProtection = true;
                    break;
                }
            }
        }

        return $runProtection;
    }
}
