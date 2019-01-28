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

use OCA\DAV\CalDAV\Reminder\AbstractNotificationProvider;
use OCA\DAV\CalDAV\Reminder\NotificationProvider\EmailProvider;
use OCA\DAV\CalDAV\Reminder\NotificationProvider\PushProvider;
use OCA\DAV\CalDAV\Reminder\ReminderService;

class NotificationProviderManager {

    /** @var EmailProvider */
    private $emailProvider;

    /** @var PushProvider */
    private $pushProvider;

    /** @var array */
    private $providers;

    /**
     * @var EmailProvider $emailProvider
     * @var PushProvider $pushProvider
     */
    public function __construct(EmailProvider $emailProvider, PushProvider $pushProvider)
    {
        $this->emailProvider = $emailProvider;
        $this->pushProvider = $pushProvider;
        $this->providers = [
            ReminderService::REMINDER_TYPE_EMAIL => $this->emailProvider,
            ReminderService::REMINDER_TYPE_DISPLAY => $this->pushProvider,
        ];
    }

    /**
     * @var string $type
     * @return AbstractNotificationProvider
     * @throws ProviderDoesNotExistsException
     */
    public function getProvider(string $type): AbstractNotificationProvider
    {
        if (in_array($type, ReminderService::REMINDER_TYPES, true)) {
            return $this->providers[$type];
        }
        throw new ProviderDoesNotExistsException($type);
    }
}