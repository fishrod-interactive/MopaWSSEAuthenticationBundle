## Introduction

The MopaWSSEAuthentication bundle is a simple and easy way to implement WSSE authentication into Symfony2 applications

## Installation

app/autoload.php

```
$loader->registerNamespaces(array(
    //other namespaces
    'Mopa' => __DIR__.'/../vendor/bundles',
  ));
```

app/AppKernel.php

```
public function registerBundles()
{
    return array(
        //other bundles
        new Mopa\Bundle\WSSEAuthenticationBundle\MopaWSSEAuthenticationBundle(),
    );
    ...
```

## Configuration

app/config/config.yml

```
# Mopa Rackspace Cloud Files configuration
mopa_wsse_authentication:
    provider_class: Mopa\Bundle\WSSEAuthenticationBundle\Security\Authentication\Provider\WsseAuthenticationProvider
    listener_class: Mopa\Bundle\WSSEAuthenticationBundle\Security\Firewall\WsseListener
    factory_class: Mopa\Bundle\WSSEAuthenticationBundle\Security\Factory\WsseFactory
```

## Usage example

app/config/security.yml

nonce_dir: location where nonces will be saved (use null to skip nonce-validation)
lifetime: lifetime of nonce
provider: user provider for wsse, optional, if not set first user provider configured will be used

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:
            nonce_dir: null
            lifetime: 300
            provider: my_user_provider

factories:
    - "%kernel.root_dir%/../vendor/bundles/Mopa/WSSEAuthenticationBundle/Resources/config/security_factories.yml"
```

## Pitfalls / Already encrypted Passwords

If you are not using the Plaintext encoder, the password the user must supply is the password you get from $user->getPassword() (for plaintext, this is the same yes!)
If you provide it on a https secured site for copy / writing it down, this should be a secure way!
The WSSE encrypting way is secure providing even plain text passwords, so using a already precrypted password is not considered to be more insecure.

This would e.g. be the case if you are using FOSUserBundle and its user provider as provider for WSSEAuthenticationBundle
