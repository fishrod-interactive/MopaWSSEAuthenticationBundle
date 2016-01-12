<?php
/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
namespace Mopa\Bundle\WSSEAuthenticationBundle\Tests\Security\Authentication\Token;

use Mopa\Bundle\WSSEAuthenticationBundle\Security\Authentication\Token\WsseToken;

/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
class TokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function getCredentials()
    {
        $token = new WsseToken();
        $this->assertEquals('', $token->getCredentials());
    }

    public function testIssetPublicVariables()
    {
        $token = new WsseToken();
        $this->assertClassHasAttribute('created', get_class($token));
        $this->assertClassHasAttribute('digest', get_class($token));
        $this->assertClassHasAttribute('nonce', get_class($token));
    }
}
