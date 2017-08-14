<?php

namespace karster\security\protection;


class CookieProtection extends VariableProtection implements ProtectionInterface
{
    public function protect()
    {
        return $this->checkVariables($_COOKIE);
    }
}