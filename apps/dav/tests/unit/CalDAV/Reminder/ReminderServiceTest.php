<?php
/**
 * @copyright Copyright (c) 2018, Thomas Citharel
 *
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
namespace OCA\DAV\Tests\unit\CalDAV\Reminder;

use Test\TestCase;
use OCA\DAV\CalDAV\Reminder\AbstractNotificationProvider;
use OCA\DAV\CalDAV\Reminder\Backend;
use OCA\DAV\CalDAV\Reminder\NotificationProviderManager;
use OCA\DAV\CalDAV\Reminder\NotificationProvider\EmailProvider;
use OCA\DAV\CalDAV\Reminder\NotificationProvider\PushProvider;
use OCA\DAV\CalDAV\Reminder\ReminderService;
use OCP\IConfig;
use OCP\IUserManager;
use OCP\IUser;

class BackendTest extends TestCase {

    /** @var Backend */
    private $backend;
    
    /** @var NotificationProviderManager */
    private $notificationProviderManager;

	/** @var IUserManager */
	private $userManager;

	/** @var IConfig */
    private $config;

    public function setUp() {
		parent::setUp();

        $this->backend = $this->createMock(Backend::class);
        $this->notificationProviderManager = $this->createMock(NotificationProviderManager::class);
        $this->userManager = $this->createMock(IUserManager::class);
        $this->config = $this->createMock(IConfig::class);
    }

    public function dataTestProcessReminders(): array
    {
        $calendarData = <<<EOD
BEGIN:VCALENDAR
PRODID:-//Nextcloud calendar v1.6.4
BEGIN:VEVENT
CREATED:20160602T133732
DTSTAMP:20160602T133732
LAST-MODIFIED:20160602T133732
UID:wej2z68l9h
SUMMARY:Test Event
LOCATION:Somewhere ...
DESCRIPTION:maybe ....
DTSTART;TZID=Europe/Berlin;VALUE=DATE:20160609
DTEND;TZID=Europe/Berlin;VALUE=DATE:20160610
BEGIN:VALARM
ACTION:EMAIL
TRIGGER:-PT15M
END:VALARM
END:VEVENT
BEGIN:VTIMEZONE
TZID:Europe/Berlin
BEGIN:DAYLIGHT
DTSTART:19810329T020000
TZNAME:MESZ
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:19961027T030000
TZNAME:MEZ
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
END:STANDARD
END:VTIMEZONE
END:VCALENDAR
EOD;

        return [
            [
                [], null
            ],
            [
                [
                    [
                        'calendardata' => $calendarData,
                        'type' => 'EMAIL',
                        'uid' => 1,
                        'id' => 1,
                    ],
                ],
                $emailProvider = $this->createMock(EmailProvider::class),
            ],
            [
                [
                    [
                        'calendardata' => $calendarData,
                        'type' => 'DISPLAY',
                        'uid' => 1,
                        'id' => 1,
                    ],
                ],
                $pushProvider = $this->createMock(PushProvider::class),
            ]
        ];
    }

    /**
     * @dataProvider dataTestProcessReminders
     */
    public function testProcessReminders(array $reminders, ?AbstractNotificationProvider $notificationProvider)
    {
        $user = $this->createMock(IUser::class);
	
        $this->backend->expects($this->once())->method('getRemindersToProcess')->willReturn($reminders);
        if (count($reminders) > 0) {
            $this->userManager->expects($this->exactly(count($reminders)))->method('get')->willReturn($user);
            $this->backend->expects($this->exactly(count($reminders)))->method('removeReminder');
            $this->notificationProviderManager->expects($this->exactly(count($reminders)))->method('getProvider')->willReturn($notificationProvider);
        }

        $reminderService = new ReminderService($this->backend, $this->notificationProviderManager, $this->userManager, $this->config);
        $reminderService->processReminders();
    }
}