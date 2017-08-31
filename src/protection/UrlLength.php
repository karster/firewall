<?php

namespace karster\security\protection;

class UrlLength extends Protection implements ProtectionInterface
{
    /**
     * @param integer $rules
     * @return $this
     */
    public function setRules(array $rules)
    {
        if (empty($rules[0])) {
            throw new \LogicException("UrlLength Rules muse be one element array example: [300]");
        }

        $this->rules = (int)($rules[0]);

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function protect()
    {
        $runProtection = false;
        $rules = $this->getRules();
        $query_string = $this->getQueryString();

        if (mb_strlen($query_string) > $rules) {
            $runProtection = true;
        }

        return $runProtection;
    }
}
