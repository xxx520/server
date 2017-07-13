<?php
declare(strict_types=1);
/**
 * @copyright 2018, Thomas Citharel <tcit@tcit.fr>
 *
 * @author Thomas Citharel <tcit@tcit.fr>
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

namespace OCA\DAV\Tests\unit\BackgroundJob;

use OCA\DAV\BackgroundJob\EventReminderJob;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use Test\TestCase;
use OCP\IUserManager;
use OCP\Notification\IManager;
use OCA\DAV\CalDAV\Reminder\Backend;
use OCA\DAV\CalDAV\Reminder\EmailNotification;

class EventReminderJobTest extends TestCase {

	/** @var IManager */
	private $notifications;

	/** @var EmailNotification */
	private $emailNotifications;

	/** @var Backend */
	private $backend;

	/** @var IUserManager */
	private $userManager;

	/** @var \OCA\DAV\BackgroundJob\EventReminderJob */
	private $backgroundJob;

	protected function setUp() {
		parent::setUp();

		$this->notifications = $this->createMock(IManager::class);
		$this->emailNotifications = $this->createMock(EmailNotification::class);
		$this->backend = $this->createMock(Backend::class);
		$this->userManager = $this->createMock(IUserManager::class);

		$this->backgroundJob = new EventReminderJob(
			$this->backend, $this->emailNotifications, $this->notifications, $this->userManager);
	}

	public function testRun() {
		$this->backend->expects($this->once())
			->method('getRemindersToProcess')
			->with()
			->will($this->returnValue([
				'notificationdate' => new \DateTime(),
				'id' => 1,
				'type' => 'EMAIL',
			]));

		$this->backgroundJob->run([]);
	}
}
