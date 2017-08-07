<?php

namespace karster\security\protection;


class CookieProtection extends VariableProtection implements RuleInterface
{
    public function protect()
    {
        return $this->checkVariables($_COOKIE);
    }
}