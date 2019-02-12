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

namespace OC\Core\Db;

use OCP\AppFramework\Db\Entity;

class LoginFlowNg extends Entity {
	/** @var int */
	protected $timestamp;
	/** @var string */
	protected $pollToken;
	/** @var string */
	protected $loginToken;
	/** @var string */
	protected $publicKey;
	/** @var string */
	protected $privateKey;
	/** @var string */
	protected $loginName;
	/** @var string */
	protected $server;
	/** @var string */
	protected $appPassword;

	public function __construct() {
		$this->addType('timestamp', 'int');
		$this->addType('pollToken', 'string');
		$this->addType('loginToken', 'string');
		$this->addType('publicKey', 'string');
		$this->addType('privateKey', 'string');
		$this->addType('loginName', 'string');
		$this->addType('server', 'string');
		$this->addType('appPassword', 'string');
	}
}
