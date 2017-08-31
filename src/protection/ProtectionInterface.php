<?php

namespace karster\security\protection;

interface ProtectionInterface
{
    /**
     * @access public
     * @return bool
     */
    public function protect();

    /**
     * @access public
     * @param $rules mixed
     * @return $this
     */
    public function setRules($rules);
}
