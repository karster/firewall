<?php

namespace karster\security\protection;

class PostProtection extends VariableProtection implements ProtectionInterface
{
    public function protect()
    {
        return $this->checkVariables($_POST);
    }
}
