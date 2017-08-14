<?php

namespace karster\security;

use karster\security\protection\Protection;

final class Firewall
{
    const WHITELIST_IP_PROTECTION = 'whitelistIp';

    const BLACKLIST_IP_PROTECTION = 'blacklistIp';

    const ATTACKER_IP_FILE = 'attackersIp.json';

    const LOG_DIRECTORY_MODE = 0777;

    /**
     * @var Protection[]
     */
    private $protection = [];

    /**
     * @var int
     */
    private $allowAttackCount = 0;

    /**
     * @var string
     */
    private $logDirectory;

    /**
     * @var bool
     */
    private $active = true;

    /**
     * Firewall constructor.
     * @param array $config
     */
    public function __construct($config = [])
    {
        if (isset($config['allowAttackCount'])) {
            $this->allowAttackCount = intval($config['allowAttackCount']);
        }

        if (isset($config['active'])) {
            $this->active = boolval($config['active']);
        }

        if (isset($config['logDirectory'])) {
            $this->logDirectory = $config['logDirectory'];
        }

        if (isset($config['protection']) && $this->active) {
            $this->protection = $this->createProtectionConfig($config);
        }
    }

    private function createProtectionConfig($config)
    {
        $result = [];
        foreach ($config['protection'] as $protectionName => $config) {
            if ($this->isProtectionActive($config)) {
                $rules = $this->getRules($config, $protectionName);
                $class = 'karster\security\protection\\' . ucfirst($protectionName);
                $result[$protectionName] = new $class($rules);
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
        if (!empty($this->protection) && !$this->canSkipProtection() && $this->active) {
            if (!$this->forceProtect()) {
                foreach ($this->protection as $protection_name => $protection) {
                    if ($protection_name != static::WHITELIST_IP_PROTECTION && $protection->protect()) {
                        $this->throwAlert($protection_name);
                        $this->createLog($protection_name);
                    }
                }
            } else {
                $this->throwAlert(static::BLACKLIST_IP_PROTECTION);
                $this->createLog(static::BLACKLIST_IP_PROTECTION);
            }
        }
    }

    /**
     * @return bool
     */
    private function canSkipProtection()
    {
        $can_skip = false;
        if (isset($this->protection[static::WHITELIST_IP_PROTECTION])) {
            $can_skip = $this->protection[static::WHITELIST_IP_PROTECTION]->protect();
        }

        return $can_skip;
    }

    /**
     * @return bool
     */
    private function forceProtect()
    {
        $force_protection = false;
        $attackers_ip = $this->getAttackerIp();

        if (isset($this->protection[static::BLACKLIST_IP_PROTECTION])) {
            $force_protection = $this->protection[static::BLACKLIST_IP_PROTECTION]->protect();
        }

        return $force_protection;
    }

    /**
     * @return array
     */
    private function getAttackerIp()
    {
        $result = [];
        if ($this->allowAttackCount > 0 && !empty($this->logDirectory) ) {
            if (!file_exists($this->logDirectory . "/" . static::ATTACKER_IP_FILE)) {
                $attackers_ip = json_encode(file_get_contents($this->logDirectory . "/" . static::ATTACKER_IP_FILE), true);
                $result = array_filter($attackers_ip, function ($value) {
                    return ($value >= $this->allowAttackCount);
                });
            }
        }

        return $result;
    }

    private function appendAttackerIp()
    {
        if ($this->logDirectory) {
            if (!file_exists($this->logDirectory . "/" . static::ATTACKER_IP_FILE)) {
                $attackers_ip = json_encode(file_get_contents($this->logDirectory . "/" . static::ATTACKER_IP_FILE), true);
            }
        }
    }

    public function throwAlert($protection_name)
    {
        echo $protection_name . "<br />";
    }

    private function createLog($protection_name)
    {
        if (!empty($this->logDirectory)) {
            if (!file_exists($this->logDirectory)) {
                mkdir($this->logDirectory, static::LOG_DIRECTORY_MODE, true);
            }

            $message = $this->createMessage($protection_name) . "\n";
            file_put_contents($this->logDirectory . '/' . $protection_name . ".txt", $message, FILE_APPEND);
        }
    }

    private function createMessage($protection_name)
    {
        $global_variable = new GlobalVariable();
        $message = [
            date('j-m-Y H:i:s'),
            $protection_name,
            "IP: " . $global_variable->getIp(),
            "DNS: " . gethostbyaddr($global_variable->getIp()),
            "User Agent: " . $global_variable->getUserAgent(),
            "URL: " . $global_variable->getRequestUri(),
            "Referer: " . $global_variable->getReferer()
        ];

        return implode(' | ', $message);
    }
}