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
use OCP\IURLGenerator;

class Notifier implements INotifier {

	public static $units = array(
        'y' => 'year',
        'm' => 'month',
        'd' => 'day',
        'h' => 'hour',
        'i' => 'minute',
        's' => 'second',
    );

	/** @var IFactory */
	protected $factory;

	/** @var IURLGenerator */
	protected $urlGenerator;

	/** @var IL10N */
	protected $l;

	public function __construct(IFactory $factory, IURLGenerator $urlGenerator) {
		$this->factory = $factory;
		$this->urlGenerator = $urlGenerator;
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
		$this->l = $this->factory->get('dav', $languageCode);

		if ($notification->getSubject() === 'calendar_reminder') {
			$subjectParameters = $notification->getSubjectParameters();
			$notification->setParsedSubject($this->processEventTitle($subjectParameters));

			$messageParameters = $notification->getMessageParameters();
			$notification->setParsedMessage($this->processEventDescription($messageParameters));
			$notification->setIcon($this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath('core', 'places/calendar.svg')));
			return $notification;
		} else {
			// Unknown subject => Unknown notification => throw
			throw new \InvalidArgumentException();
		}
	}

	/**
	 * @param int $startDate
	 * @return string
	 */
	private function processEventTitle(array $event)
	{
		$event_datetime = new \DateTime();
		$event_datetime->setTimestamp($event['start']);
		$now = new \DateTime();

		$diff = $event_datetime->diff($now);

		foreach (self::$units as $attribute => $unit) {
            $count = $diff->$attribute;
            if (0 !== $count) {
                return $this->getPluralizedTitle($count, $diff->invert, $unit, $event['title']);
            }
        }
        return '';
	}

	/**
	 * @var int $count
	 * @var int $invert
	 * @var string $unit
	 * @return string
	 */
	private function getPluralizedTitle(int $count, int $invert, string $unit, string $title)
	{
		if ($invert) {
			return $this->l->n('%s (in one %s)', '%s (in %s %ss)', $count, [$title, $count, $unit]);
		}
		// This should probably not show up
		return $this->l->t('%s (one %s ago)', '%s (%s %ss ago)', $count, [$title, $unit, $count]);
	}

	private function processEventDescription(array $event)
	{
		return $event['when'] . "<br>" . $event['description'] . "<br>" . $event['location'];
	}
}