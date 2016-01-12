<?php

namespace Mopa\Bundle\WSSEAuthenticationBundle\Tests\Security\Firewall;

use Mopa\Bundle\WSSEAuthenticationBundle\Security\Authentication\Token\WsseToken;
use Mopa\Bundle\WSSEAuthenticationBundle\Security\Firewall\WsseListener;
use Symfony\Component\HttpFoundation\Response;

class ListenerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject $responseEvent
     */
    private $responseEvent;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $request;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $tokenStorage;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $authenticationManager;

    protected function setUp()
    {
        $this->responseEvent = $this->getMockBuilder('\Symfony\Component\HttpKernel\Event\GetResponseEvent')->disableOriginalConstructor()->getMock();
        $this->request = $this->getMockForAbstractClass('Symfony\Component\HttpFoundation\Request');
        $this->responseEvent->expects($this->once())->method('getRequest')->will($this->returnValue($this->request));
        $this->tokenStorage = $this->getMock('\Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $this->authenticationManager = $this->getMock('\Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
    }

    /**
     * @test
     */
    public function handleUnauthorized()
    {
        $listener = new WsseListener($this->tokenStorage, $this->authenticationManager);
        $response = new Response();
        $response->setStatusCode(403);//unauthorized
        $this->responseEvent->expects($this->once())->method('setResponse')->with($response);
        $listener->handle($this->responseEvent);
    }

    /**
     * @test
     */
    public function handleForbidden()
    {
        $listener = new WsseListener($this->tokenStorage, $this->authenticationManager);
        $this->request->headers->add(array('X-WSSE'=>'temp'));
        $response = new Response();
        $response->setStatusCode(403);//unauthorized
        $this->responseEvent->expects($this->once())->method('setResponse')->with($response);
        $listener->handle($this->responseEvent);
    }

    /**
     * @test
     */
    public function handleReturnToken()
    {
        $token = new WsseToken();
        $token->setUser('admin');
        $token->digest = 'admin';
        $token->nonce = 'admin';
        $token->created = '2010-12-12 20:00:00';
        $tokenMock2 = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->will($this->returnValue($tokenMock2));
        $this->tokenStorage->expects($this->once())->method('setToken')->with($tokenMock2);
        $this->request->headers->add(array('X-WSSE'=>'UsernameToken Username="admin", PasswordDigest="admin", Nonce="admin", Created="2010-12-12 20:00:00"'));
        $listener = new WsseListener($this->tokenStorage, $this->authenticationManager);
        $listener->handle($this->responseEvent);
    }

    /**
     * @test
     */
    public function handleReturnResponse()
    {
        $token = new WsseToken();
        $token->setUser('admin');
        $token->digest = 'admin';
        $token->nonce = 'admin';
        $token->created = '2010-12-12 20:00:00';
        $response = new Response();
        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->will($this->returnValue($response));
        $this->responseEvent->expects($this->once())->method('setResponse')->with($response);
        $this->request->headers->add(array('X-WSSE'=>'UsernameToken Username="admin", PasswordDigest="admin", Nonce="admin", Created="2010-12-12 20:00:00"'));
        $listener = new WsseListener($this->tokenStorage, $this->authenticationManager);
        $listener->handle($this->responseEvent);
    }

}
