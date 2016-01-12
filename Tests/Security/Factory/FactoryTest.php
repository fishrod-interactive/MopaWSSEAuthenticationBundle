<?php
/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
namespace Mopa\Bundle\WSSEAuthenticationBundle\Tests\Security\Factory;

use Mopa\Bundle\WSSEAuthenticationBundle\Security\Factory\WsseFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function getPosition()
    {
        $factory = new WsseFactory();
        $result = $factory->getPosition();
        $this->assertEquals('pre_auth', $result);
    }

    /**
     * @test
     */
    public function getKey()
    {
        $factory = new WsseFactory();
        $result = $factory->getKey();
        $this->assertEquals('wsse', $result);
        $this->assertEquals('wsse', $this->getFactory()->getKey());
    }

    protected function getFactory()
    {
        return $this->getMockForAbstractClass('Mopa\Bundle\WSSEAuthenticationBundle\Security\Factory\WsseFactory', array());
    }

    public function testCreate($key = 'foo')
    {
        $factory = $this->getFactory();

        $container = new ContainerBuilder();
        $container->register('wsse.security.authentication.provider');

        list($authProviderId,
             $listenerId,
             $entryPointId
        ) = $factory->create($container, $key, ['nonce_dir' => 'nonce', 'lifetime' => 300], 'user_provider', 'entry_point');

        // auth provider
        $this->assertEquals('mopa_wsse_authentication.' . $key, $authProviderId);
        $this->assertEquals('mopa_wsse_authentication.security.listener.' . $key, $listenerId);
        $this->assertEquals('entry_point', $entryPointId);
        $this->assertTrue($container->hasDefinition('mopa_wsse_authentication.security.listener.foo'));
        $definition = $container->getDefinition('mopa_wsse_authentication.foo');

        $this->assertEquals(
            [
                'index_0' => $key,
                'index_1' => 'nonce',
                'index_2' => 300,
                0 => new Reference('user_provider'),
                1 => new Reference('security.user_checker')
            ],
            $definition->getArguments()
        );
        $this->assertTrue($container->hasDefinition('mopa_wsse_authentication.' . $key));
    }
}
