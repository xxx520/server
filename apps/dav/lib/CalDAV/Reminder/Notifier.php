<?php
/**
 * @copyright Copyright (c) 2017 Thomas Citharel <tcit@tcit.fr>
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

namespace OCA\DAV\CalDAV\Reminder;

use OCA\DAV\AppInfo\Application;
use OCP\L10N\IFactory;
use OCP\Notification\INotification;
use OCP\Notification\INotifier;

class Notifier implements INotifier {
	protected $factory;

	public function __construct(IFactory $factory) {
		$this->factory = $factory;
	}

	/**
	 * @param INotification $notification
	 * @param string $languageCode The code of the language that should be used to prepare the notification
	 * @return INotification
	 */
	public function prepare(INotification $notification, $languageCode) {
		if ($notification->getApp() !== Application::APP_ID) {
			throw new \InvalidArgumentException();
		}

		// Read the language from the notification
		$l = $this->factory->get('dav', $languageCode);

		if ($notification->getSubject() === 'calendar_reminder') {
			$subjectParams = $notification->getSubjectParameters();
			$event_datetime = new \DateTime();
			$event_datetime->setTimestamp($subjectParams[1]);
			$notification->setParsedSubject($l->t('Your event "%s" is in %s', [$subjectParams[0], $event_datetime->format('Y-m-d H:i:s')]));
			$messageParams = $notification->getMessageParameters();
			if (isset($messageParams[0]) && $messageParams[0] !== '') {
				$notification->setParsedMessage($messageParams[0]);
			}
			// $notification->setIcon($this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, 'app-dark.svg')));
			return $notification;
		} else {
			// Unknown subject => Unknown notification => throw
			throw new \InvalidArgumentException();
		}
	}
}