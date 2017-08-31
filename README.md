# Firewall

[![Build Status](https://travis-ci.org/karster/firewall.svg?branch=master)][travis]
[![Latest Stable Version](https://poser.pugx.org/karster/security/v/stable)][version]
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)][license]

> Simple firewall to protect your web application against many attacks

## Installation

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```shell
composer require karster/firewall:"dev-master"
```

or add

```
"karster/firewall": "dev-master"
```

to the require section of your composer.json.

## Usage
```php
require __DIR__ . '/vendor/autoload.php';

$config = [
    'logDirectory' => __DIR__ . "/firewall_logs",
    'logFilesCount' => 10,
    'allowAttackCount' => 5,
    'active' => true,
    'protection' => [
        'allowedRequestMethod' => [
            'active' => true
        ],
        'allowedGlobals' => [
            'active' => false
        ],
        'urlLength' => [
            'active' => true,
            'rules' => 200,
        ],
        'getProtection' => [
            'active' => true,
            'rules' => ['select', 'from'],
        ],
        'urlProtection' => [
            'active' => true,
            'rulesFile' => 'path/to/rulesFile.json'
        ],
        'whitelistIp' => [
            'active' => true,
            'rules' => ['127.0.0.1', '::1']
        ],
        'blacklistIp' => [
            'active' => true,
            'rules' => ['23.254.0.1', '22.23.22.8']
        ]
    ]
];

$firewall = new \karster\security\Firewall($config);
$firewall->run();

```

or

```php
require __DIR__ . '/vendor/autoload.php';

$protections = [
    'allowedRequestMethod' => [
        'active' => true
    ],
    'allowedGlobals' => [
        'active' => false
    ],
    'urlLength' => [
        'active' => true,
        'rules' => 200,
    ],
    'getProtection' => [
        'active' => true,
        'rules' => ['select', 'from'],
    ],
    'urlProtection' => [
        'active' => true,
        'rulesFile' => 'path/to/rulesFile.json'
    ],
    'whitelistIp' => [
        'active' => true,
        'rules' => ['127.0.0.2', '127.0.0.3']
    ],
    'blacklistIp' => [
        'active' => true,
        'rules' => ['127.0.0.1', '::1']
    ]
];

$firewall = new \karster\security\Firewall();
$firewall->setAllowAttackCount(5)
         ->setActive(true)
         ->setLogDirectory(__DIR__ . "/firewall_logs")
         ->setLogFilesCount(10)
         ->setProtection($protections)
         ->run();

```

* logDirectory - `string` - path to directory where firewall can writes
* logFilesCount - `integer` - delete older logs than specific count. Set `0` to disable
* allowAttackCount - `integer` - attack count from same IP address before blacklisting (**logDirectory** is required). Set `0` to disable
* active - `boolean` - default `true` 
* protection - `array` - associative array of protections where key is protection name and value is protection configuration

## Protections
We can chose different types of protection:
* allowedRequestMethod
* allowedGlobals
* blacklistIp
* cookieProtection
* getProtection
* postProtection
* sessionProtection
* urlLength
* urlProtection

Every protection contains configuration array with parameters:
* active `boolen` - default `true`
* rules `array|integer` - every protection accept array except **urlLength** protection witch accept integer
* rulesFile `string` - path to json file with rules

```php
'cookieProtection' => [
    'active' => true,
    'rules' => [
        'select', 'from', 'where'
    ],
    // or
    'rulesFile' => 'path/to/rulesFile.json'
]

```

If isn't set `rules` or `rulesFile` use default rules.

## Tests

```
./vendor/bin/phpunit -c phpunit.xml
```

## Contribution
Have an idea? Found a bug? See [how to contribute][contributing].

## License
MIT see [LICENSE][] for the full license text.

[version]: https://packagist.org/packages/karster/security
[travis]: https://travis-ci.org/karster/firewall
[license]: LICENSE.md
[contributing]: CONTRIBUTING.md