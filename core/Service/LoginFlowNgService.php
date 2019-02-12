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

namespace OC\Core\Service;

use OC\Core\Data\LoginFlowNgTokens;
use OC\Core\Db\LoginFlowNg;
use OC\Core\Db\LoginFlowNgMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\ILogger;
use OCP\Security\ICrypto;
use OCP\Security\ISecureRandom;

class LoginFlowNgService {

	/** @var LoginFlowNgMapper */
	private $mapper;
	/** @var ISecureRandom */
	private $random;
	/** @var ITimeFactory */
	private $time;
	/** @var IConfig */
	private $config;
	/** @var ICrypto */
	private $crypto;
	/** @var ILogger */
	private $logger;

	public function __construct(LoginFlowNgMapper $mapper,
								ISecureRandom $random,
								ITimeFactory $time,
								IConfig $config,
								ICrypto $crypto,
								ILogger $logger) {
		$this->mapper = $mapper;
		$this->random = $random;
		$this->time = $time;
		$this->config = $config;
		$this->crypto = $crypto;
		$this->logger = $logger;
	}

	public function createTokens(): LoginFlowNgTokens {
		$flow = new LoginFlowNg();
		$pollToken = $this->random->generate(128, ISecureRandom::CHAR_DIGITS.ISecureRandom::CHAR_LOWER.ISecureRandom::CHAR_UPPER);
		$loginToken = $this->random->generate(128, ISecureRandom::CHAR_DIGITS.ISecureRandom::CHAR_LOWER.ISecureRandom::CHAR_UPPER);
		$flow->setPollToken($this->hashToken($pollToken));
		$flow->setLoginToken($loginToken);
		$flow->setStarted(0);
		$flow->setTimestamp($this->time->getTime());

		[$publicKey, $privateKey] = $this->getKeyPair();
		$privateKey = $this->crypto->encrypt($privateKey, $pollToken);

		$flow->setPublicKey($publicKey);
		$flow->setPrivateKey($privateKey);

		$this->mapper->insert($flow);

		return new LoginFlowNgTokens($loginToken, $pollToken);
	}

	private function hashToken(string $token): string {
		$secret = $this->config->getSystemValue('secret');
		return hash('sha512', $token . $secret);
	}

	private function getKeyPair(): array {
		$config = array_merge([
			'digest_alg' => 'sha512',
			'private_key_bits' => 2048,
		], $this->config->getSystemValue('openssl', []));

		// Generate new key
		$res = openssl_pkey_new($config);
		if ($res === false) {
			$this->logOpensslError();
			throw new \RuntimeException('Could not initialize keys');
		}

		openssl_pkey_export($res, $privateKey);

		// Extract the public key from $res to $pubKey
		$publicKey = openssl_pkey_get_details($res);
		$publicKey = $publicKey['key'];

		return [$publicKey, $privateKey];
	}

	private function logOpensslError() {
		$errors = [];
		while ($error = openssl_error_string()) {
			$errors[] = $error;
		}
		$this->logger->critical('Something is wrong with your openssl setup: ' . implode(', ', $errors));
	}
}
