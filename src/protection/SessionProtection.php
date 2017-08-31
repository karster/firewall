<?php

namespace karster\security\protection;

class SessionProtection extends VariableProtection
{
    public function protect()
    {
        return $this->checkVariables($_SESSION);
    }
}
