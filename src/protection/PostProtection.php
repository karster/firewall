<?php

namespace karster\security\protection;


class PostProtection extends VariableProtection implements RuleInterface
{
    public function protect()
    {
        return $this->checkVariables($_POST);
    }
}