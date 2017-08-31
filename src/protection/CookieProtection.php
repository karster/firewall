<?php

namespace karster\security\protection;

class CookieProtection extends VariableProtection
{
    public function protect()
    {
        return $this->checkVariables($_COOKIE);
    }
}
