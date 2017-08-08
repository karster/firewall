<?php

namespace karster\security\protection;


class UrlLength extends Rule implements RuleInterface
{
    /**
     * @param integer $rules
     * @return $this
     */
    public function setRules($rules)
    {
        $this->rules = intval($rules);

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