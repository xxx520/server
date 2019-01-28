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
namespace OCA\DAV\CalDAV\Reminder;

use \DateTime;
use OC\BackgroundJob\TimedJob;
use OCA\DAV\CalDAV\Reminder\Backend;
use OCA\DAV\CalDAV\Reminder\NotificationProviderManager;
use OCA\DAV\CalDAV\Reminder\NotificationProvider\EmailProvider;
use OCA\DAV\CalDAV\Reminder\NotificationProvider\PushProvider;
use OCP\L10N\IFactory as L10NFactory;
use OCP\IUserManager;
use OCP\IConfig;
use Sabre\VObject\Component\VCalendar;
use Sabre\VObject\Component\VEvent;
use Sabre\VObject\DateTimeParser;
use Sabre\VObject\Parameter;
use Sabre\VObject\Property;
use Sabre\VObject\Recur\EventIterator;
use Sabre\VObject\Reader;

class ReminderService {

    /** @var Backend */
    private $backend;
    
    /** @var NotificationProviderManager */
    private $notificationProviderManager;

	/** @var IUserManager */
	private $userManager;

	/** @var IConfig */
    private $config;
    
    const REMINDER_TYPE_EMAIL = 'EMAIL';
    const REMINDER_TYPE_DISPLAY = 'DISPLAY';

    const REMINDER_TYPES = [self::REMINDER_TYPE_EMAIL, self::REMINDER_TYPE_DISPLAY];

    public function __construct(Backend $backend,
                                NotificationProviderManager $notificationProviderManager,
								IUserManager $userManager,
								IConfig $config) {
        $this->backend = $backend;
        $this->notificationProviderManager = $notificationProviderManager;
		$this->userManager = $userManager;
		$this->config = $config;
    }
    
    /**
     * Process reminders to activate
     */
    public function processReminders()
    {
        $reminders = $this->backend->getRemindersToProcess();

		error_log('reminder background job run');
		foreach ($reminders as $reminder) {
			error_log('running reminder');
			$calendarData = Reader::read($reminder['calendardata']);

            if (!in_array($reminder['type'], self::REMINDER_TYPES)) {
                break;
            }

			$user = $this->userManager->get($reminder['uid']);

			$notification = $this->notificationProviderManager->getProvider($reminder['type'])->send($calendarData, $user);
			$this->backend->removeReminder($reminder['id']);
		}
    }
}