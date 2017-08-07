<?php

namespace karster\security;

final class Firewall
{
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
        if (!empty($this->protection)) {
            foreach ($this->protection as $protectionName => $protection) {
                if ($protection->protect()) {
                    $this->throwAlert($protectionName);
                }
            }
        }
    }

    private function throwAlert($protectionName)
    {
        echo $protectionName . "<br />";
    }
}