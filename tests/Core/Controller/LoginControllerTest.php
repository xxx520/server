<?php
/**
 * @author Lukas Reschke <lukas@owncloud.com>
 *
 * @copyright Copyright (c) 2016, ownCloud, Inc.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace Tests\Core\Controller;

use OC\Authentication\Token\IToken;
use OC\Authentication\TwoFactorAuth\Manager;
use OC\Authentication\TwoFactorAuth\ProviderSet;
use OC\Core\Controller\LoginController;
use OC\Security\Bruteforce\Throttler;
use OC\User\Session;
use OCA\TwoFactorBackupCodes\Provider\BackupCodesProvider;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Defaults;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use Test\TestCase;

class LoginControllerTest extends TestCase {
	/** @var LoginController */
	private $loginController;
	/** @var IRequest|\PHPUnit_Framework_MockObject_MockObject */
	private $request;
	/** @var IUserManager|\PHPUnit_Framework_MockObject_MockObject */
	private $userManager;
	/** @var IConfig|\PHPUnit_Framework_MockObject_MockObject */
	private $config;
	/** @var ISession|\PHPUnit_Framework_MockObject_MockObject */
	private $session;
	/** @var Session|\PHPUnit_Framework_MockObject_MockObject */
	private $userSession;
	/** @var IURLGenerator|\PHPUnit_Framework_MockObject_MockObject */
	private $urlGenerator;
	/** @var ILogger|\PHPUnit_Framework_MockObject_MockObject */
	private $logger;
	/** @var Manager|\PHPUnit_Framework_MockObject_MockObject */
	private $twoFactorManager;
	/** @var Defaults|\PHPUnit_Framework_MockObject_MockObject */
	private $defaults;
	/** @var Throttler|\PHPUnit_Framework_MockObject_MockObject */
	private $throttler;

	public function setUp() {
		parent::setUp();
		$this->request = $this->createMock(IRequest::class);
		$this->userManager = $this->createMock(\OC\User\Manager::class);
		$this->config = $this->createMock(IConfig::class);
		$this->session = $this->createMock(ISession::class);
		$this->userSession = $this->createMock(Session::class);
		$this->urlGenerator = $this->createMock(IURLGenerator::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->twoFactorManager = $this->createMock(Manager::class);
		$this->defaults = $this->createMock(Defaults::class);
		$this->throttler = $this->createMock(Throttler::class);

		$this->request->method('getRemoteAddress')
			->willReturn('1.2.3.4');
		$this->throttler->method('getDelay')
			->with(
				$this->equalTo('1.2.3.4'),
				$this->equalTo('')
			)->willReturn(1000);

		$this->loginController = new LoginController(
			'core',
			$this->request,
			$this->userManager,
			$this->config,
			$this->session,
			$this->userSession,
			$this->urlGenerator,
			$this->logger,
			$this->twoFactorManager,
			$this->defaults,
			$this->throttler
		);
	}

	public function testLogoutWithoutToken() {
		$this->request
			->expects($this->once())
			->method('getCookie')
			->with('nc_token')
			->willReturn(null);
		$this->config
			->expects($this->never())
			->method('deleteUserValue');
		$this->urlGenerator
			->expects($this->once())
			->method('linkToRouteAbsolute')
			->with('core.login.showLoginForm')
			->willReturn('/login');

		$expected = new RedirectResponse('/login');
		$expected->addHeader('Clear-Site-Data', '"cache", "storage", "executionContexts"');
		$this->assertEquals($expected, $this->loginController->logout());
	}

	public function testLogoutWithToken() {
		$this->request
			->expects($this->once())
			->method('getCookie')
			->with('nc_token')
			->willReturn('MyLoginToken');
		$user = $this->createMock(IUser::class);
		$user
			->expects($this->once())
			->method('getUID')
			->willReturn('JohnDoe');
		$this->userSession
			->expects($this->once())
			->method('getUser')
			->willReturn($user);
		$this->config
			->expects($this->once())
			->method('deleteUserValue')
			->with('JohnDoe', 'login_token', 'MyLoginToken');
		$this->urlGenerator
			->expects($this->once())
			->method('linkToRouteAbsolute')
			->with('core.login.showLoginForm')
			->willReturn('/login');

		$expected = new RedirectResponse('/login');
		$expected->addHeader('Clear-Site-Data', '"cache", "storage", "executionContexts"');
		$this->assertEquals($expected, $this->loginController->logout());
	}

	public function testShowLoginFormForLoggedInUsers() {
		$this->userSession
			->expects($this->once())
			->method('isLoggedIn')
			->willReturn(true);

		$expectedResponse = new RedirectResponse(\OC_Util::getDefaultPageUrl());
		$this->assertEquals($expectedResponse, $this->loginController->showLoginForm('', '', ''));
	}

	public function testShowLoginFormWithErrorsInSession() {
		$this->userSession
			->expects($this->once())
			->method('isLoggedIn')
			->willReturn(false);
		$this->session
			->expects($this->once())
			->method('get')
			->with('loginMessages')
			->willReturn(
				[
					[
						'ErrorArray1',
						'ErrorArray2',
					],
					[
						'MessageArray1',
						'MessageArray2',
					],
				]
			);

		$expectedResponse = new TemplateResponse(
			'core',
			'login',
			[
				'ErrorArray1' => true,
				'ErrorArray2' => true,
				'messages' => [
					'MessageArray1',
					'MessageArray2',
				],
				'loginName' => '',
				'user_autofocus' => true,
				'canResetPassword' => true,
				'alt_login' => [],
				'resetPasswordLink' => null,
				'throttle_delay' => 1000,
				'login_form_autocomplete' => 'off',
			],
			'guest'
		);
		$this->assertEquals($expectedResponse, $this->loginController->showLoginForm('', '', ''));
	}

	public function testShowLoginFormForFlowAuth() {
		$this->userSession
			->expects($this->once())
			->method('isLoggedIn')
			->willReturn(false);

		$expectedResponse = new TemplateResponse(
			'core',
			'login',
			[
				'messages' => [],
				'redirect_url' => 'login/flow',
				'loginName' => '',
				'user_autofocus' => true,
				'canResetPassword' => true,
				'alt_login' => [],
				'resetPasswordLink' => null,
				'throttle_delay' => 1000,
				'login_form_autocomplete' => 'off',
			],
			'guest'
		);
		$this->assertEquals($expectedResponse, $this->loginController->showLoginForm('', 'login/flow', ''));
	}

	/**
	 * @return array
	 */
	public function passwordResetDataProvider() {
		return [
			[
				true,
				true,
			],
			[
				false,
				false,
			],
		];
	}

	/**
	 * @dataProvider passwordResetDataProvider
	 */
	public function testShowLoginFormWithPasswordResetOption($canChangePassword,
															 $expectedResult) {
		$this->userSession
			->expects($this->once())
			->method('isLoggedIn')
			->willReturn(false);
		$this->config
			->expects($this->exactly(2))
			->method('getSystemValue')
			->will($this->returnValueMap([
			['login_form_autocomplete', true, true],
			['lost_password_link', '', false],
		]));
		$user = $this->createMock(IUser::class);
		$user
			->expects($this->once())
			->method('canChangePassword')
			->willReturn($canChangePassword);
		$this->userManager
			->expects($this->once())
			->method('get')
			->with('LdapUser')
			->willReturn($user);

		$expectedResponse = new TemplateResponse(
			'core',
			'login',
			[
				'messages' => [],
				'loginName' => 'LdapUser',
				'user_autofocus' => false,
				'canResetPassword' => $expectedResult,
				'alt_login' => [],
				'resetPasswordLink' => false,
				'throttle_delay' => 1000,
				'login_form_autocomplete' => 'on',
			],
			'guest'
		);
		$this->assertEquals($expectedResponse, $this->loginController->showLoginForm('LdapUser', '', ''));
	}

	/**
	 * Asserts that a disabled user can't login and gets the expected response.
	 */
	public function testLoginForDisabledUser() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->method('getUID')
			->willReturn('uid');
		$user->method('isEnabled')
			->willReturn(false);

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);

		$this->userSession
			->method('isLoggedIn')
			->willReturn(false);

		$loginName = 'iMDisabled';
		$password = 'secret';

		$this->session
			->expects($this->once())
			->method('set')
			->with('loginMessages', [
				[LoginController::LOGIN_MSG_USERDISABLED], []
			]);

		$this->userManager
			->expects($this->once())
			->method('get')
			->with($loginName)
			->willReturn($user);

		$expected = new RedirectResponse('');
		$expected->throttle(['user' => $loginName]);

		$response =	$this->loginController->tryLogin(
			$loginName, $password, null, false, 'Europe/Berlin', '1'
		);
		$this->assertEquals($expected, $response);
	}

	public function testShowLoginFormForUserNamed0() {
		$this->userSession
			->expects($this->once())
			->method('isLoggedIn')
			->willReturn(false);
		$this->config
			->expects($this->exactly(2))
			->method('getSystemValue')
			->will($this->returnValueMap([
			['login_form_autocomplete', true, true],
			['lost_password_link', '', false],
		]));
		$user = $this->createMock(IUser::class);
		$user->expects($this->once())
			->method('canChangePassword')
			->willReturn(false);
		$this->userManager
			->expects($this->once())
			->method('get')
			->with('0')
			->willReturn($user);

		$expectedResponse = new TemplateResponse(
			'core',
			'login',
			[
				'messages' => [],
				'loginName' => '0',
				'user_autofocus' => false,
				'canResetPassword' => false,
				'alt_login' => [],
				'resetPasswordLink' => false,
				'throttle_delay' => 1000,
				'login_form_autocomplete' => 'on',
			],
			'guest'
		);
		$this->assertEquals($expectedResponse, $this->loginController->showLoginForm('0', '', ''));
	}

	public function testLoginWithInvalidCredentials() {
		$user = 'MyUserName';
		$password = 'secret';
		$loginPageUrl = '/login?redirect_url=/apps/files';

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);
		$this->userManager->expects($this->once())
			->method('checkPasswordNoLogging')
			->will($this->returnValue(false));
		$this->userManager->expects($this->once())
			->method('getByEmail')
			->with($user)
			->willReturn([]);
		$this->urlGenerator->expects($this->once())
			->method('linkToRoute')
			->with('core.login.showLoginForm', [
				'user' => 'MyUserName',
				'redirect_url' => '/apps/files',
			])
			->will($this->returnValue($loginPageUrl));

		$this->userSession->expects($this->never())
			->method('createSessionToken');
		$this->userSession->expects($this->never())
			->method('createRememberMeToken');
		$this->config->expects($this->never())
			->method('deleteUserValue');

		$expected = new \OCP\AppFramework\Http\RedirectResponse($loginPageUrl);
		$expected->throttle(['user' => 'MyUserName']);
		$this->assertEquals($expected, $this->loginController->tryLogin($user, $password, '/apps/files'));
	}

	public function testLoginWithValidCredentials() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('uid'));
		$loginName = 'loginli';
		$user->expects($this->any())
			->method('getLastLogin')
			->willReturn(123456);
		$password = 'secret';
		$indexPageUrl = \OC_Util::getDefaultPageUrl();

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);
		$this->userManager->expects($this->once())
			->method('checkPasswordNoLogging')
			->will($this->returnValue($user));
		$this->userSession->expects($this->once())
			->method('completeLogin')
			->with($user, ['loginName' => $loginName, 'password' => $password]);
		$this->userSession->expects($this->once())
			->method('createSessionToken')
			->with($this->request, $user->getUID(), $loginName, $password, IToken::REMEMBER);
		$this->twoFactorManager->expects($this->once())
			->method('isTwoFactorAuthenticated')
			->with($user)
			->will($this->returnValue(false));
		$this->config->expects($this->once())
			->method('deleteUserValue')
			->with('uid', 'core', 'lostpassword');
		$this->config->expects($this->once())
			->method('setUserValue')
			->with('uid', 'core', 'timezone', 'Europe/Berlin');
		$this->config
			->method('getSystemValue')
			->with('remember_login_cookie_lifetime')
			->willReturn(1234);
		$this->userSession->expects($this->never())
			->method('createRememberMeToken');

		$this->session->expects($this->exactly(2))
			->method('set')
			->withConsecutive(
				['last-password-confirm', 123456],
				['timezone', '1']
			);

		$expected = new \OCP\AppFramework\Http\RedirectResponse($indexPageUrl);
		$this->assertEquals($expected, $this->loginController->tryLogin($loginName, $password, null, false, 'Europe/Berlin', '1'));
	}

	public function testLoginWithValidCredentialsAndRememberMe() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('uid'));
		$loginName = 'loginli';
		$password = 'secret';
		$indexPageUrl = \OC_Util::getDefaultPageUrl();

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);
		$this->userManager->expects($this->once())
			->method('checkPasswordNoLogging')
			->will($this->returnValue($user));
		$this->userSession->expects($this->once())
			->method('completeLogin')
			->with($user, ['loginName' => $loginName, 'password' => $password]);
		$this->userSession->expects($this->once())
			->method('createSessionToken')
			->with($this->request, $user->getUID(), $loginName, $password, true);
		$this->twoFactorManager->expects($this->once())
			->method('isTwoFactorAuthenticated')
			->with($user)
			->will($this->returnValue(false));
		$this->config->expects($this->once())
			->method('deleteUserValue')
			->with('uid', 'core', 'lostpassword');
		$this->config
			->method('getSystemValue')
			->with('remember_login_cookie_lifetime')
			->willReturn(1234);
		$this->userSession->expects($this->once())
			->method('createRememberMeToken')
			->with($user);

		$expected = new \OCP\AppFramework\Http\RedirectResponse($indexPageUrl);
		$this->assertEquals($expected, $this->loginController->tryLogin($loginName, $password, null, true));
	}

	public function testLoginWithoutPassedCsrfCheckAndNotLoggedIn() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('jane'));
		$password = 'secret';
		$originalUrl = 'another%20url';

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(false);
		$this->userSession->expects($this->once())
			->method('isLoggedIn')
			->with()
			->will($this->returnValue(false));
		$this->config->expects($this->never())
			->method('deleteUserValue');
		$this->userSession->expects($this->never())
			->method('createRememberMeToken');

		$expected = new \OCP\AppFramework\Http\RedirectResponse(\OC_Util::getDefaultPageUrl());
		$this->assertEquals($expected, $this->loginController->tryLogin('Jane', $password, $originalUrl));
	}

	public function testLoginWithoutPassedCsrfCheckAndLoggedIn() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('jane'));
		$password = 'secret';
		$originalUrl = 'another%20url';
		$redirectUrl = 'http://localhost/another url';

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(false);
		$this->userSession->expects($this->once())
			->method('isLoggedIn')
			->with()
			->will($this->returnValue(true));
		$this->urlGenerator->expects($this->once())
			->method('getAbsoluteURL')
			->with(urldecode($originalUrl))
			->will($this->returnValue($redirectUrl));
		$this->config->expects($this->never())
			->method('deleteUserValue');
		$this->userSession->expects($this->never())
			->method('createRememberMeToken');
		$this->config
			->method('getSystemValue')
			->with('remember_login_cookie_lifetime')
			->willReturn(1234);

		$expected = new \OCP\AppFramework\Http\RedirectResponse($redirectUrl);
		$this->assertEquals($expected, $this->loginController->tryLogin('Jane', $password, $originalUrl));
	}

	public function testLoginWithValidCredentialsAndRedirectUrl() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('jane'));
		$password = 'secret';
		$originalUrl = 'another%20url';
		$redirectUrl = 'http://localhost/another url';

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);
		$this->userManager->expects($this->once())
			->method('checkPasswordNoLogging')
			->with('Jane', $password)
			->will($this->returnValue($user));
		$this->userSession->expects($this->once())
			->method('createSessionToken')
			->with($this->request, $user->getUID(), 'Jane', $password, IToken::REMEMBER);
		$this->userSession->expects($this->once())
			->method('isLoggedIn')
			->with()
			->will($this->returnValue(true));
		$this->urlGenerator->expects($this->once())
			->method('getAbsoluteURL')
			->with(urldecode($originalUrl))
			->will($this->returnValue($redirectUrl));
		$this->config->expects($this->once())
			->method('deleteUserValue')
			->with('jane', 'core', 'lostpassword');
		$this->config
			->method('getSystemValue')
			->with('remember_login_cookie_lifetime')
			->willReturn(1234);

		$expected = new \OCP\AppFramework\Http\RedirectResponse(urldecode($redirectUrl));
		$this->assertEquals($expected, $this->loginController->tryLogin('Jane', $password, $originalUrl));
	}

	public function testLoginWithOneTwoFactorProvider() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('john'));
		$password = 'secret';
		$challengeUrl = 'challenge/url';
		$provider1 = $this->createMock(IProvider::class);
		$provider1->method('getId')->willReturn('u2f');
		$provider2 = $this->createMock(BackupCodesProvider::class);
		$provider2->method('getId')->willReturn('backup');

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);
		$this->userManager->expects($this->once())
			->method('checkPasswordNoLogging')
			->will($this->returnValue($user));
		$this->userSession->expects($this->once())
			->method('completeLogin')
			->with($user, ['loginName' => 'john@doe.com', 'password' => $password]);
		$this->userSession->expects($this->once())
			->method('createSessionToken')
			->with($this->request, $user->getUID(), 'john@doe.com', $password, IToken::REMEMBER);
		$this->twoFactorManager->expects($this->once())
			->method('isTwoFactorAuthenticated')
			->with($user)
			->will($this->returnValue(true));
		$this->twoFactorManager->expects($this->once())
			->method('prepareTwoFactorLogin')
			->with($user);
		$providerSet = new ProviderSet([$provider1, $provider2], false);
		$this->twoFactorManager->expects($this->once())
			->method('getProviderSet')
			->with($user)
			->willReturn($providerSet);
		$this->urlGenerator->expects($this->once())
			->method('linkToRoute')
			->with('core.TwoFactorChallenge.showChallenge', [
				'challengeProviderId' => 'u2f',
			])
			->will($this->returnValue($challengeUrl));
		$this->config->expects($this->once())
			->method('deleteUserValue')
			->with('john', 'core', 'lostpassword');
		$this->config
			->method('getSystemValue')
			->with('remember_login_cookie_lifetime')
			->willReturn(1234);
		$this->userSession->expects($this->never())
			->method('createRememberMeToken');

		$expected = new RedirectResponse($challengeUrl);
		$this->assertEquals($expected, $this->loginController->tryLogin('john@doe.com', $password, null));
	}

	public function testLoginWithMultipleTwoFactorProviders() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('john'));
		$password = 'secret';
		$challengeUrl = 'challenge/url';
		$provider1 = $this->createMock(IProvider::class);
		$provider2 = $this->createMock(IProvider::class);
		$provider1->method('getId')->willReturn('prov1');
		$provider2->method('getId')->willReturn('prov2');

		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);
		$this->userManager->expects($this->once())
			->method('checkPasswordNoLogging')
			->will($this->returnValue($user));
		$this->userSession->expects($this->once())
			->method('completeLogin')
			->with($user, ['loginName' => 'john@doe.com', 'password' => $password]);
		$this->userSession->expects($this->once())
			->method('createSessionToken')
			->with($this->request, $user->getUID(), 'john@doe.com', $password, IToken::REMEMBER);
		$this->twoFactorManager->expects($this->once())
			->method('isTwoFactorAuthenticated')
			->with($user)
			->will($this->returnValue(true));
		$this->twoFactorManager->expects($this->once())
			->method('prepareTwoFactorLogin')
			->with($user);
		$providerSet = new ProviderSet([$provider1, $provider2], false);
		$this->twoFactorManager->expects($this->once())
			->method('getProviderSet')
			->with($user)
			->willReturn($providerSet);
		$this->urlGenerator->expects($this->once())
			->method('linkToRoute')
			->with('core.TwoFactorChallenge.selectChallenge')
			->will($this->returnValue($challengeUrl));
		$this->config->expects($this->once())
			->method('deleteUserValue')
			->with('john', 'core', 'lostpassword');
		$this->config
			->method('getSystemValue')
			->with('remember_login_cookie_lifetime')
			->willReturn(1234);
		$this->userSession->expects($this->never())
			->method('createRememberMeToken');

		$expected = new RedirectResponse($challengeUrl);
		$this->assertEquals($expected, $this->loginController->tryLogin('john@doe.com', $password, null));
	}

	public function testToNotLeakLoginName() {
		/** @var IUser|\PHPUnit_Framework_MockObject_MockObject $user */
		$user = $this->createMock(IUser::class);
		$user->expects($this->any())
			->method('getUID')
			->will($this->returnValue('john'));

		$this->userManager->expects($this->once())
			->method('checkPasswordNoLogging')
			->with('john@doe.com', 'just wrong')
			->willReturn(false);
		$this->userManager->expects($this->once())
			->method('checkPassword')
			->with('john', 'just wrong')
			->willReturn(false);

		$this->userManager->expects($this->once())
			->method('getByEmail')
			->with('john@doe.com')
			->willReturn([$user]);

		$this->urlGenerator->expects($this->once())
			->method('linkToRoute')
			->with('core.login.showLoginForm', ['user' => 'john@doe.com'])
			->will($this->returnValue(''));
		$this->request
			->expects($this->once())
			->method('passesCSRFCheck')
			->willReturn(true);
		$this->config->expects($this->never())
			->method('deleteUserValue');
		$this->userSession->expects($this->never())
			->method('createRememberMeToken');

		$expected = new RedirectResponse('');
		$expected->throttle(['user' => 'john']);
		$this->assertEquals($expected, $this->loginController->tryLogin('john@doe.com', 'just wrong', null));
	}
}
