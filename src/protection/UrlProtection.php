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
        if (!empty($rules) && is_array($rules)) {
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

        if (!empty($query_string)) {
            $rules = $this->getRules();
            $count = 0;
            str_replace($rules, '*', $query_string, $count);

            if ($count > 0) {
                $runProtection = true;
            }

            if (preg_match('#\w?\s?union\s\w*?\s?(select|all|distinct|insert|update|drop|delete)#is', $query_string)) {
                $runProtection = true;
            }

            if (preg_match('/([OdWo5NIbpuU4V2iJT0n]{5}) /', rawurldecode($query_string))) {
                $runProtection = true;
            }

            if (strstr(rawurldecode($query_string), '*')) {
                $runProtection = true;
            }
        }

        return $runProtection;
    }
}
