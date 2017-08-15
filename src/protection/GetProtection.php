<?php

namespace karster\security\protection;

class GetProtection extends VariableProtection implements ProtectionInterface
{
    public function protect()
    {
        return $this->checkVariables($_GET);
    }
}
