<?php

namespace karster\security;

final class Firewall
{
    const WHITELIST_IP_PROTECTION = 'whitelistIp';

    const BLACKLIST_IP_PROTECTION = 'blacklistIp';

    private $protection = [];

    public function __construct($config = [])
    {
        if (isset($config['protection'])) {
            $this->protection = $this->createProtectionConfig($config);
        }
    }

    private function createProtectionConfig($config)
    {
        $result = [];
        foreach ($config['protection'] as $protection => $config) {
            if ($this->isProtectionActive($config)) {
                $rules = $this->getRules($config, $protection);
                $class = 'karster\security\protection\\' . ucfirst($protection);
                $result[$protection] = new $class($rules);
            }
        }

        return $result;
    }

    private function isProtectionActive($config)
    {
        return isset($config['active']) && boolval($config['active']);
    }

    private function getRules($config, $protection)
    {
        if (isset($config['rules'])) {
            return $config['rules'];
        }

        return $this->loadDefaultRules($protection);
    }

    private function loadDefaultRules($protection)
    {
        $rules = [];
        $file = __DIR__ . '/defaultRules/' . lcfirst($protection) . '.json';

        if (file_exists($file)) {
            $rules = json_decode(file_get_contents($file), true);
        }

        return $rules;
    }

    public function run()
    {
        if (!empty($this->protection) && !$this->canSkipProtection()) {
            if (!$this->forceProtect()) {
                foreach ($this->protection as $protectionName => $protection) {
                    if ($protectionName != static::WHITELIST_IP_PROTECTION && $protection->protect()) {
                        $this->throwAlert($protectionName);
                    }
                }
            } else {
                $this->throwAlert(static::BLACKLIST_IP_PROTECTION);
            }
        }
    }

    /**
     * @return bool
     */
    private function canSkipProtection()
    {
        $can_skip = false;
        if ($this->protection[static::WHITELIST_IP_PROTECTION]) {
            $can_skip = $this->protection[static::WHITELIST_IP_PROTECTION]->protect();
        }

        return $can_skip;
    }

    private function forceProtect()
    {
        $force_protection = false;
        if ($this->protection[static::BLACKLIST_IP_PROTECTION]) {
            $force_protection = $this->protection[static::BLACKLIST_IP_PROTECTION]->protect();
        }

        return $force_protection;
    }

    private function throwAlert($protectionName)
    {
        echo $protectionName . "<br />";
    }
}