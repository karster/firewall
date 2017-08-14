<?php

namespace karster\security\protection;


class SessionProtection extends VariableProtection implements ProtectionInterface
{
    public function protect()
    {
        return $this->checkVariables($_SESSION);
    }
}