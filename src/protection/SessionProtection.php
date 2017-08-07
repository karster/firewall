<?php

namespace karster\security\protection;


class SessionProtection extends VariableProtection implements RuleInterface
{
    public function protect()
    {
        return $this->checkVariables($_SESSION);
    }
}