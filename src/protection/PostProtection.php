<?php

namespace karster\security\protection;

class PostProtection extends VariableProtection
{
    public function protect()
    {
        return $this->checkVariables($_POST);
    }
}
