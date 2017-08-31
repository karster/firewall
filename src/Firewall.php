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
     * @var string
     */
    private $messageTemplate = 'I\'m detecting an attack on system!<br /><br />Your IP address {IP} with other data have been recorded and sent to your ISP.';

    /**
     * Firewall constructor.
     * @param array $config
     */
    public function __construct($config = [])
    {
        if (isset($config['allowAttackCount'])) {
            $this->allowAttackCount = (int)$config['allowAttackCount'];
        }

        if (isset($config['active'])) {
            $this->active = (bool)$config['active'];
        }

        if (isset($config['logDirectory'])) {
            $this->logDirectory = $config['logDirectory'];
        }

        if (isset($config['protection']) && $this->active) {
            $this->protection = $this->createProtectionConfig($config['protection']);
        }
    }

    /**
     * @param $attack_count
     * @return $this
     */
    public function setAllowAttackCount($attack_count)
    {
        $this->allowAttackCount = (int)$attack_count;

        return $this;
    }

    /**
     * @param $active
     * @return $this
     */
    public function setActive($active)
    {
        $this->active = (bool)$active;

        return $this;
    }

    /**
     * @param $directory
     * @return $this
     */
    public function setLogDirectory($directory)
    {
        $this->logDirectory = $directory;

        return $this;
    }

    /**
     * @param $protection
     * @return $this
     */
    public function setProtection($protection)
    {
        if ($this->active) {
            $this->protection = $this->createProtectionConfig($protection);
        }

        return $this;
    }

    /**
     * @param $protection
     * @return array
     */
    private function createProtectionConfig($protection)
    {
        $result = [];
        foreach ($protection as $protectionName => $config) {
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
        return isset($config['active']) ? (bool)$config['active'] : true;
    }

    /**
     * @param $config
     * @param $protection
     * @return array|mixed
     */
    private function getRules($config, $protection)
    {
        if (!empty($config['rules'])) {
            return $config['rules'];
        }

        if (!empty($config['rulesFile'])) {
            return $this->loadRulesFromFile($config['rulesFile'], false);
        }

        return $this->loadRulesFromFile(__DIR__ . '/defaultRules/' . lcfirst($protection) . '.json');
    }

    /**
     * @param $file
     * @param bool $default_rule
     * @return array
     * @throws \Exception
     */
    private function loadRulesFromFile($file, $default_rule = true)
    {
        $rules = [];
        if (file_exists($file)) {
            $rules = json_decode(file_get_contents($file), true);
        } elseif (!$default_rule) {
            throw new \Exception('File not found');
        }

        return $rules;
    }

    public function run()
    {
        if ($this->active && !empty($this->protection) && !$this->canSkipProtection()) {
            if (!$this->forceProtect()) {
                foreach ($this->protection as $protection_name => $protection) {
                    if ($protection_name != static::WHITELIST_IP_PROTECTION && $protection->protect()) {
                        $this->appendAttackerIp();
                        $this->createLog($protection_name);
                        $this->throwAlert();
                    }
                }
            } else {
                $this->createLog(static::BLACKLIST_IP_PROTECTION);
                $this->throwAlert();
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

        if (!empty($attackers_ip) && !$force_protection) {
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

    public function throwAlert()
    {
        echo '
            <html>
                <head>
                    <meta charset="UTF-8" />
                    <title>Firewall</title>
                </head>
                <body style="background-color:#D64541">
                    <h1 style="width:80%;margin:80px auto;color:#fff;text-align:center;">
                        ' . $this->getMessage() . '
                    </h1>
                </body>
            </html>';

        exit();
    }

    private function getMessage()
    {
        $variables = [
            '{IP}' => $this->getIp(),
            '{USER_AGENT}' => $this->getUserAgent(),
            '{DNS}' => gethostbyaddr($this->getIp()),
            '{REFERER}' => $this->getReferer()
        ];

        return str_replace(array_keys($variables), array_values($variables), $this->messageTemplate);
    }

    /**
     * @param $protection_name
     */
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

    /**
     * @param $protection_name
     * @return string
     */
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
