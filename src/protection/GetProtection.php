<?php

namespace karster\security\protection;

class GetProtection extends VariableProtection
{
    public function protect()
    {
        return $this->checkVariables($_GET);
    }
}
