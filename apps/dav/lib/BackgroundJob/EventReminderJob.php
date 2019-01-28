<?php
/**
 * @author Thomas Citharel <tcit@tcit.fr>
 *
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
namespace OCA\DAV\BackgroundJob;

use OCA\DAV\CalDAV\Reminder\ReminderService;
use OCP\BackgroundJob\TimedJob;

class EventReminderJob extends TimedJob {

	/** @var ReminderService */
	private $reminderService;

	public function __construct(ReminderService $reminderService) {
		$this->reminderService = $reminderService;
		/** Run every 15 minutes */
		$this->setInterval(0);
	}

	/**
	 * @param $arg
	 */
	public function run($arg) {
		$this->reminderService->processReminders();
	}
}