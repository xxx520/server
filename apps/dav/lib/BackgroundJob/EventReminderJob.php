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

use OCA\DAV\AppInfo\Application;
use OC\BackgroundJob\TimedJob;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager;
use OCP\Notification\INotification;
use OCP\Util;
use Sabre\VObject\Component;
use Sabre\VObject\Reader;
use OCA\DAV\CalDAV\Reminder\Backend;
use OCA\DAV\CalDAV\Reminder\EmailNotification;

class EventReminderJob extends TimedJob {

	/** @var IManager */
	private $notifications;

	/** @var EmailNotification */
	private $emailNotification;

	/** @var Backend */
	private $backend;

	/** @var IUserManager */
	private $usermanager;

	public function __construct(Backend $backend, EmailNotification $emailNotification, IManager $notifications, IUserManager $usermanager) {
		$this->notifications = $notifications;
		$this->backend = $backend;
		$this->usermanager = $usermanager;
		$this->emailNotification = $emailNotification;

		/** Run every 15 minutes */
		$this->setInterval(10);
	}

	/**
	 * @param $arg
	 */
	public function run($arg) {
		$reminders = $this->backend->getRemindersToProcess();

		error_log('reminder background job run');
		foreach ($reminders as $reminder) {
			$calendarData = Reader::read($reminder['calendardata']);

			$reminderDetails = $this->getDetails($reminder);

			if ($reminder['type'] === 'EMAIL') {
				$this->emailNotification->sendEmail($calendarData, 'toto', 'tata');
			} elseif ($reminder['type'] === 'DISPLAY') {
				$this->sendNotification($this->usermanager->get($reminder['uid']), $reminderDetails);
			}
			$this->backend->removeReminder($reminder['id']);
		}
	}

	private function getDetails(array $reminder)
	{
		$component = null;

		/**
		 * Get the real event
		 */
		foreach($reminder['eventData']->getComponents() as $component) {
			/** @var Component $component */
			if ($component->name === 'VEVENT') {
				break;
			}
		}

		/**
		 * Try to get geocoordinates
		 */
		$geo = null;
		if (isset($component->GEO)) {
			list($geo['lat'], $geo['long']) = explode(';', $component->GEO, 2);
		}

		/**
		 * Build the list of attendees
		 */


		return [
			'title' => (string) $component->SUMMARY,
			'start' => $component->DTSTART->getDateTime(),
			'location' => $component->LOCATION,
			'geo' => $geo,
			'description' => $component->DESCRIPTION,
			'calendarName' => $reminder['displayname'],
			'participants' => $component->ATTENDEE,
			'notificationdate' => $reminder['notificationdate'],
			'uri' => $reminder['objecturi'],
		];
	}

	// private function sendMail(IUser $user, array $details) {

	// 	$message = $this->mailer->createMessage();
	// 	$template = $this->mailer->createEMailTemplate();

	// 	$template->addHeader();
	// 	$template->addHeading($this->l10n->t('Notification: %s - ', [$details['title']]) . $this->l10n->l('datetime', $details['start']));

	// 	$template->addBodyText($this->l10n->t('Hello,'));

	// 	$template->addBodyText($details['title']);

	// 	if ($details['location']) {
	// 		if ($details['geo']) {
	// 			// if we have exact coordinates, put a link to OSM on the location string
	// 			$template->addBodyButton($this->l10n->t('Where: %s', [$details['location']]), 'https://www.openstreetmap.org/#map=16/' . $details['geo']['lat'] . '/' . $details['geo']['long']);
	// 		} else {
	// 			// if we have a location field, show it
	// 			$template->addBodyText($this->l10n->t('Where: %s', [$details['location']]));
	// 		}
	// 	}

	// 	$template->addBodyText($this->l10n->t('Calendar: %s', [$details['calendarName']]));

	// 	if ($details['participants']) {
	// 		$template->addBodyText($this->l10n->t('Attendees: %s', [implode(', ', $details['participants'])]));
	// 	}

	// 	$body = $template->renderHtml();
	// 	$plainBody = $template->renderText();

	// 	$from = Util::getDefaultEmailAddress('register');

	// 	$message->setFrom([$from => $this->defaults->getName()]);
	// 	$message->setTo([$user->getEMailAddress() => 'Recipient']);
	// 	$message->setPlainBody($plainBody);
	// 	$message->setHtmlBody($body);

	// 	$this->mailer->send($message);
	// }

	private function sendNotification(IUser $user, $reminder) {
		/** @var INotification $notification */
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($user->getUID())
			//->setDateTime(\DateTime::createFromFormat('U', $reminder['notificationdate']))
			->setDateTime(new \DateTime())
			->setObject(Application::APP_ID, $reminder['uri']) // $type and $id
			->setSubject('calendar_reminder', [$reminder['title'], $reminder['start']->getTimeStamp()]) // $subject and $parameters
			->setMessage('calendar_reminder', ['hurry up !'])
		;
		$this->notifications->notify($notification);
	}
}