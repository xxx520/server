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

use OC\Core\Exception\LoginFlowV2NotFoundException;
use OC\Core\Service\LoginFlowV2Service;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;
use OCP\IURLGenerator;

class ClientFlowLoginV2Controller extends Controller {

	/** @var LoginFlowV2Service */
	private $loginFlowNgService;
	/** @var IURLGenerator */
	private $urlGenerator;

	public function __construct(string $appName,
								IRequest $request,
								LoginFlowV2Service $loginFlowNgService,
								IURLGenerator $urlGenerator) {
		parent::__construct($appName, $request);
		$this->loginFlowNgService = $loginFlowNgService;
		$this->urlGenerator = $urlGenerator;
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 */
	public function poll(string $token): JSONResponse {
		try {
			$creds = $this->loginFlowNgService->poll($token);
		} catch (LoginFlowV2NotFoundException $e) {
			return new JSONResponse([], Http::STATUS_NOT_FOUND);
		}

		return new JSONResponse($creds);
	}

	public function showAuthPickerPage() {

	}

	public function landing(string $token) {

	}

	public function grantPage() {

	}

	public function done() {

	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * TODO: rate limiting
	 */
	public function init(): JSONResponse {
		//TODO: catch errors
		$tokens = $this->loginFlowNgService->createTokens();

		$data = [
			'poll' => [
				'token' => $tokens->getPollToken(),
				'endpoint' => $this->urlGenerator->linkToRouteAbsolute('core.ClientFlowLoginV2.poll')
			],
			'login' => $this->urlGenerator->linkToRouteAbsolute('core.ClientFlowLoginV2.landing', ['token' => $tokens->getLoginToken()]),
		];

		return new JSONResponse($data);
	}
}
