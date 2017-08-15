<?php

namespace karster\security;

use karster\security\protection\BlacklistIp;
use karster\security\protection\Protection;

final class Firewall
{
    use GlobalVariableTrait;

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
                        $this->appendAttackerIp();
                        $this->createLog($protection_name);
                        $this->throwAlert($protection_name);
                    }
                }
            } else {
                $this->createLog(static::BLACKLIST_IP_PROTECTION);
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
        $attackers_ip = $this->getAttackerIpList();

        if (isset($this->protection[static::BLACKLIST_IP_PROTECTION])) {
            $rules = $this->protection[static::BLACKLIST_IP_PROTECTION]->getRules();
            $rules = array_merge($rules, $attackers_ip);
            $this->protection[static::BLACKLIST_IP_PROTECTION]->setRules($rules);
            $force_protection = $this->protection[static::BLACKLIST_IP_PROTECTION]->protect();
        }

        if (!empty($attackers_ip)) {
            $ip_protection = new BlacklistIp($attackers_ip);
            $force_protection = $ip_protection->protect();
        }

        return $force_protection;
    }

    /**
     * @return array
     */
    private function getAttackerIpList()
    {
        $result = [];

        if ($this->allowAttackCount > 0 && !empty($this->logDirectory) && file_exists($this->logDirectory . "/" . static::ATTACKER_IP_FILE)) {
            $attackers_ip = json_decode(file_get_contents($this->logDirectory . "/" . static::ATTACKER_IP_FILE), true);
            $result = array_filter($attackers_ip, function ($value) {
                return ($value >= $this->allowAttackCount);
            });

            $result = array_keys($result);
        }

        return $result;
    }
    
    private function appendAttackerIp()
    {
        if (!empty($this->logDirectory) && file_exists($this->logDirectory)) {
            $ip = $this->getIp();
            $attackers_ip = json_decode(file_get_contents($this->logDirectory . "/" . static::ATTACKER_IP_FILE), true);
            if (isset($attackers_ip[$ip])) {
                $attackers_ip[$ip]++;
            } else {
                $attackers_ip[$ip] = 1;
            }

            file_put_contents($this->logDirectory . "/" . static::ATTACKER_IP_FILE, json_encode($attackers_ip));
        }
    }

    public function throwAlert($protection_name)
    {
        echo $protection_name . "<br />";
        exit();
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
        $message = [
            date('j-m-Y H:i:s'),
            $protection_name,
            "IP: " . $this->getIp(),
            "DNS: " . gethostbyaddr($this->getIp()),
            "User Agent: " . $this->getUserAgent(),
            "URL: " . $this->getRequestUri(),
            "Referer: " . $this->getReferer()
        ];

        return implode(' | ', $message);
    }
}
