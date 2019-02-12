<?php
declare(strict_types=1);
/**
 * @copyright Copyright (c) 2019, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OC\Core\Controller;

use OC\Authentication\Exceptions\InvalidTokenException;
use OC\Authentication\Exceptions\PasswordlessTokenException;
use OC\Authentication\Token\IProvider;
use OC\Authentication\Token\IToken;
use OC\Core\Exception\LoginFlowV2NotFoundException;
use OC\Core\Service\LoginFlowV2Service;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\Defaults;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserSession;
use OCP\Security\ISecureRandom;
use OCP\Session\Exceptions\SessionNotAvailableException;

class ClientFlowLoginV2Controller extends Controller {

	private const tokenName = 'client.flow.v2.login.token';
	private const stateName = 'client.flow.v2.state.token';

	/** @var LoginFlowV2Service */
	private $loginFlowV2Service;
	/** @var IURLGenerator */
	private $urlGenerator;
	/** @var ISession */
	private $session;
	/** @var ISecureRandom */
	private $random;
	/** @var Defaults */
	private $defaults;
	/** @var IProvider */
	private $tokenProvider;
	/** @var IUserSession */
	private $userSession;
	/** @var IL10N */
	private $l10n;

	public function __construct(string $appName,
								IRequest $request,
								LoginFlowV2Service $loginFlowV2Service,
								IURLGenerator $urlGenerator,
								ISession $session,
								ISecureRandom $random,
								Defaults $defaults,
								IProvider $tokenProvider,
								IUserSession $userSession,
								IL10N $l10n) {
		parent::__construct($appName, $request);
		$this->loginFlowV2Service = $loginFlowV2Service;
		$this->urlGenerator = $urlGenerator;
		$this->session = $session;
		$this->random = $random;
		$this->defaults = $defaults;
		$this->tokenProvider = $tokenProvider;
		$this->userSession = $userSession;
		$this->l10n = $l10n;
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * //TODO: rate limit
	 */
	public function poll(string $token): JSONResponse {
		try {
			$creds = $this->loginFlowV2Service->poll($token);
		} catch (LoginFlowV2NotFoundException $e) {
			return new JSONResponse([], Http::STATUS_NOT_FOUND);
		}

		return new JSONResponse($creds);
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 * @UseSession
	 */
	public function showAuthPickerPage() {
		if (!$this->isValidLoginToken()) {
			return $this->loginTokenForbiddenResponse();
		}

		$stateToken = $this->random->generate(
			64,
			ISecureRandom::CHAR_LOWER.ISecureRandom::CHAR_UPPER.ISecureRandom::CHAR_DIGITS
		);
		$this->session->set(self::stateName, $stateToken);

		return new StandaloneTemplateResponse(
			$this->appName,
			'loginflowv2/authpicker',
			[
				'client' => 'AWESOME CLIENT', //TODO fix name
				'instanceName' => $this->defaults->getName(),
				'urlGenerator' => $this->urlGenerator,
				'stateToken' => $this->session->get(self::stateName),
			],
			'guest'
		);
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 * @UseSession
	 */
	public function landing(string $token): Response {
		if (!$this->loginFlowV2Service->startLoginFlow($token)) {
			return $this->loginTokenForbiddenResponse();
		}

		$this->session->set(self::tokenName, $token);

		return new RedirectResponse(
			$this->urlGenerator->linkToRouteAbsolute('core.ClientFlowLoginV2.showAuthPickerPage')
		);
	}

	/**
	 * @NoAdminRequired
	 * @UseSession
	 * @NoCSRFRequired
	 * @NoSameSiteCookieRequired
	 */
	public function grantPage(string $stateToken): StandaloneTemplateResponse {
		if(!$this->isValidStateToken($stateToken)) {
			return $this->stateTokenForbiddenResponse();
		}

		if (!$this->isValidLoginToken()) {
			return $this->loginTokenForbiddenResponse();
		}

		return new StandaloneTemplateResponse(
			$this->appName,
			'loginflowv2/grant',
			[
				'client' => 'AWESOME CLIENT',
				'instanceName' => $this->defaults->getName(),
				'urlGenerator' => $this->urlGenerator,
				'stateToken' => $stateToken,
			],
			'guest'
		);
	}

	/**
	 * @NoAdminRequired
	 * @UseSession
	 */
	public function generateAppPassword(string $stateToken): Response {
		if(!$this->isValidStateToken($stateToken)) {
			return $this->stateTokenForbiddenResponse();
		}

		if (!$this->isValidLoginToken()) {
			return $this->loginTokenForbiddenResponse();
		}

		$loginToken = $this->session->get(self::tokenName);

		// Clear session variables
		$this->session->remove(self::tokenName);
		$this->session->remove(self::stateName);

		try {
			$sessionId = $this->session->getId();
		} catch (SessionNotAvailableException $ex) {
			$response = new Response();
			$response->setStatus(Http::STATUS_FORBIDDEN);
			return $response;
		}

		try {
			$sessionToken = $this->tokenProvider->getToken($sessionId);
			$loginName = $sessionToken->getLoginName();
			try {
				$password = $this->tokenProvider->getPassword($sessionToken, $sessionId);
			} catch (PasswordlessTokenException $ex) {
				$password = null;
			}
		} catch (InvalidTokenException $ex) {
			$response = new Response();
			$response->setStatus(Http::STATUS_FORBIDDEN);
			return $response;
		}

		$token = $this->random->generate(72, ISecureRandom::CHAR_UPPER.ISecureRandom::CHAR_LOWER.ISecureRandom::CHAR_DIGITS);
		$uid = $this->userSession->getUser()->getUID();
		$generatedToken = $this->tokenProvider->generateToken(
			$token,
			$uid,
			$loginName,
			$password,
			'AWESOME CLIENT', // TODO fixme!
			IToken::PERMANENT_TOKEN,
			IToken::DO_NOT_REMEMBER
		);

		$this->loginFlowV2Service->flowDone($loginToken, $this->getServerPath(), $loginName, $token);

		return new StandaloneTemplateResponse(
			$this->appName,
			'loginflowv2/done',
			[],
			'guest'
		);


	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * TODO: rate limiting
	 */
	public function init(): JSONResponse {
		//TODO: catch errors
		$tokens = $this->loginFlowV2Service->createTokens();

		$data = [
			'poll' => [
				'token' => $tokens->getPollToken(),
				'endpoint' => $this->urlGenerator->linkToRouteAbsolute('core.ClientFlowLoginV2.poll')
			],
			'login' => $this->urlGenerator->linkToRouteAbsolute('core.ClientFlowLoginV2.landing', ['token' => $tokens->getLoginToken()]),
		];

		return new JSONResponse($data);
	}

	private function isValidStateToken(string $stateToken): bool {
		$currentToken = $this->session->get(self::stateName);
		if(!is_string($stateToken) || !is_string($currentToken)) {
			return false;
		}
		return hash_equals($currentToken, $stateToken);
	}

	private function stateTokenForbiddenResponse(): StandaloneTemplateResponse {
		$response = new StandaloneTemplateResponse(
			$this->appName,
			'403',
			[
				'message' => $this->l10n->t('State token does not match'),
			],
			'guest'
		);
		$response->setStatus(Http::STATUS_FORBIDDEN);
		return $response;
	}

	private function isValidLoginToken(): bool {
		$currentToken = $this->session->get(self::tokenName);
		if(!is_string($currentToken)) {
			return false;
		}

		return $this->loginFlowV2Service->isLoginTokenValid($currentToken);
	}

	private function loginTokenForbiddenResponse(): StandaloneTemplateResponse {
		$response = new StandaloneTemplateResponse(
			$this->appName,
			'403',
			[
				'message' => $this->l10n->t('Your login token is invalid or has expired'),
			],
			'guest'
		);
		$response->setStatus(Http::STATUS_FORBIDDEN);
		return $response;
	}

	private function getServerPath(): string {
		$serverPostfix = '';

		if (strpos($this->request->getRequestUri(), '/index.php') !== false) {
			$serverPostfix = substr($this->request->getRequestUri(), 0, strpos($this->request->getRequestUri(), '/index.php'));
		} else if (strpos($this->request->getRequestUri(), '/login/flow') !== false) {
			$serverPostfix = substr($this->request->getRequestUri(), 0, strpos($this->request->getRequestUri(), '/login/flow'));
		}

		$protocol = $this->request->getServerProtocol();

		if ($protocol !== "https") {
			$xForwardedProto = $this->request->getHeader('X-Forwarded-Proto');
			$xForwardedSSL = $this->request->getHeader('X-Forwarded-Ssl');
			if ($xForwardedProto === 'https' || $xForwardedSSL === 'on') {
				$protocol = 'https';
			}
		}

		return $protocol . "://" . $this->request->getServerHost() . $serverPostfix;
	}
}
