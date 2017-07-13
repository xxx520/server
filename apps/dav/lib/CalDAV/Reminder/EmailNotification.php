<?php
/**
 * @copyright Copyright (c) 2018 Thomas Citharel <tcit@tcit.fr>
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

namespace OCA\DAV\CalDAV\Reminder;

use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IURLGenerator;
use OCP\L10N\IFactory as L10NFactory;
use OCP\Mail\IEMailTemplate;
use OCP\Mail\IMailer;
use Sabre\VObject\Component\VCalendar;
use Sabre\VObject\Component\VEvent;
use Sabre\VObject\DateTimeParser;
use Sabre\VObject\Parameter;
use Sabre\VObject\Property;
use Sabre\VObject\Recur\EventIterator;

class EmailNotification
{

	/** @var string */
	private $userId;

	/** @var IConfig */
	private $config;

	/** @var IMailer */
	private $mailer;

	/** @var ILogger */
	private $logger;

	/** @var L10NFactory */
	private $l10nFactory;

	/** @var IURLGenerator */
	private $urlGenerator;

	/**
	 * @param IConfig $config
	 * @param IMailer $mailer
	 * @param ILogger $logger
	 * @param L10NFactory $l10nFactory
	 * @param IUrlGenerator $urlGenerator
	 * @param IDBConnection $db
	 * @param string $userId
	 */
	public function __construct(IConfig $config, IMailer $mailer, ILogger $logger,
								L10NFactory $l10nFactory,
								IURLGenerator $urlGenerator,
								string $userId) {
		$this->userId = $userId;
		$this->config = $config;
		$this->mailer = $mailer;
		$this->logger = $logger;
		$this->l10nFactory = $l10nFactory;
		$this->urlGenerator = $urlGenerator;
	}

	/**
	 * Event handler for the 'schedule' event.
	 *
	 * @param VCalendar $vcalendar
	 * @param string $lang
	 * @return void
	 */
	public function sendEmail(VCalendar $vcalendar, string $recipientName, string $recipient, string $lang = 'en') {
		$vevent = $vcalendar->VEVENT;
		$summary = $vevent->SUMMARY;

		// move before
		$defaultLang = $this->l10nFactory->findLanguage();
		$l10n = $this->l10nFactory->get('dav', $lang);

		$title = $vevent->SUMMARY;
		$description = $vevent->DESCRIPTION;

		$start = $vevent->DTSTART;
		if (isset($vevent->DTEND)) {
			$end = $vevent->DTEND;
		} elseif (isset($vevent->DURATION)) {
			$isFloating = $vevent->DTSTART->isFloating();
			$end = clone $vevent->DTSTART;
			$endDateTime = $end->getDateTime();
			$endDateTime = $endDateTime->add(DateTimeParser::parse($vevent->DURATION->getValue()));
			$end->setDateTime($endDateTime, $isFloating);
		} elseif (!$vevent->DTSTART->hasTime()) {
			$isFloating = $vevent->DTSTART->isFloating();
			$end = clone $vevent->DTSTART;
			$endDateTime = $end->getDateTime();
			$endDateTime = $endDateTime->modify('+1 day');
			$end->setDateTime($endDateTime, $isFloating);
		} else {
			$end = clone $vevent->DTSTART;
		}

		$when = $this->generateWhenString($l10n, $start, $end);

		$url = $vevent->URL;
		$location = $vevent->LOCATION;

		$defaultVal = '--';

		$data = array(
			'title' => (string)$title ?: $defaultVal,
			'description' => (string)$description ?: $defaultVal,
			'url' => (string)$url ?: $defaultVal,
		);

		$fromEMail = \OCP\Util::getDefaultEmailAddress('invitations-noreply');

		$message = $this->mailer->createMessage()
			->setFrom([$fromEMail => 'Nextcloud']) // TODO : reply me
			// ->setReplyTo([$sender => $senderName])
			->setTo([$recipient => $recipientName]);

		$template = $this->mailer->createEMailTemplate('dav.calendarReminder', $data);
		$template->addHeader();

		$this->addSubjectAndHeading($template, $l10n, $summary);
		$this->addBulletList($template, $l10n, $when, $location, $description, $url);
//		$this->addResponseButtons($template, $l10n, $iTipMessage, $lastOccurrence);

		$template->addFooter();
		$message->useTemplate($template);

		$attachment = $this->mailer->createAttachment(
			$vcalendar->serialize(),
			'event.ics',// TODO(leon): Make file name unique, e.g. add event id
			'text/calendar'
		);
		$message->attach($attachment);

		try {
			$failed = $this->mailer->send($message);
			if ($failed) {
				$this->logger->error('Unable to deliver message to {failed}', ['app' => 'dav', 'failed' =>  implode(', ', $failed)]);
			}
		} catch(\Exception $ex) {
			$this->logger->logException($ex, ['app' => 'dav']);
		}
	}

	/**
	 * @param IL10N $l10n
	 * @param Property $dtstart
	 * @param Property $dtend
	 */
	private function generateWhenString(IL10N $l10n, Property $dtstart, Property $dtend)
	{
		$isAllDay = $dtstart instanceof Property\ICalendar\Date;

		/** @var Property\ICalendar\Date | Property\ICalendar\DateTime $dtstart */
		/** @var Property\ICalendar\Date | Property\ICalendar\DateTime $dtend */
		/** @var \DateTimeImmutable $dtstartDt */
		$dtstartDt = $dtstart->getDateTime();
		/** @var \DateTimeImmutable $dtendDt */
		$dtendDt = $dtend->getDateTime();

		$diff = $dtstartDt->diff($dtendDt);

		$dtstartDt = new \DateTime($dtstartDt->format(\DateTime::ATOM));
		$dtendDt = new \DateTime($dtendDt->format(\DateTime::ATOM));

		if ($isAllDay) {
			// One day event
			if ($diff->days === 1) {
				return $l10n->l('date', $dtstartDt, ['width' => 'medium']);
			}

			//event that spans over multiple days
			$localeStart = $l10n->l('date', $dtstartDt, ['width' => 'medium']);
			$localeEnd = $l10n->l('date', $dtendDt, ['width' => 'medium']);

			return $localeStart . ' - ' . $localeEnd;
		}

		/** @var Property\ICalendar\DateTime $dtstart */
		/** @var Property\ICalendar\DateTime $dtend */
		$isFloating = $dtstart->isFloating();
		$startTimezone = $endTimezone = null;
		if (!$isFloating) {
			$prop = $dtstart->offsetGet('TZID');
			if ($prop instanceof Parameter) {
				$startTimezone = $prop->getValue();
			}

			$prop = $dtend->offsetGet('TZID');
			if ($prop instanceof Parameter) {
				$endTimezone = $prop->getValue();
			}
		}

		$localeStart = $l10n->l('weekdayName', $dtstartDt, ['width' => 'abbreviated']) . ', ' .
			$l10n->l('datetime', $dtstartDt, ['width' => 'medium|short']);

		// always show full date with timezone if timezones are different
		if ($startTimezone !== $endTimezone) {
			$localeEnd = $l10n->l('datetime', $dtendDt, ['width' => 'medium|short']);

			return $localeStart . ' (' . $startTimezone . ') - ' .
				$localeEnd . ' (' . $endTimezone . ')';
		}

		// show only end time if date is the same
		if ($this->isDayEqual($dtstartDt, $dtendDt)) {
			$localeEnd = $l10n->l('time', $dtendDt, ['width' => 'short']);
		} else {
			$localeEnd = $l10n->l('weekdayName', $dtendDt, ['width' => 'abbreviated']) . ', ' .
				$l10n->l('datetime', $dtendDt, ['width' => 'medium|short']);
		}

		return  $localeStart . ' - ' . $localeEnd . ' (' . $startTimezone . ')';
	}

	/**
	 * @param \DateTime $dtStart
	 * @param \DateTime $dtEnd
	 * @return bool
	 */
	private function isDayEqual(\DateTime $dtStart, \DateTime $dtEnd) {
		return $dtStart->format('Y-m-d') === $dtEnd->format('Y-m-d');
	}

	/**
	 * @param IEMailTemplate $template
	 * @param IL10N $l10n
	 * @param string $method
	 * @param string $summary
	 * @param string $attendeeName
	 * @param string $inviteeName
	 */
	private function addSubjectAndHeading(IEMailTemplate $template, IL10N $l10n, $summary)
	{
		$template->setSubject('Event: ' . $summary);
		$template->addHeading($l10n->t('Don\'t forget to go to %1$s ', [$summary]));
	}

    /**
	 * @param IEMailTemplate $template
	 * @param IL10N $l10n
	 * @param string $time
	 * @param string $location
	 * @param string $description
	 * @param string $url
	 */
	private function addBulletList(IEMailTemplate $template, IL10N $l10n, $time, $location, $description, $url) {
		$template->addBodyListItem($time, $l10n->t('When:'),
			$this->getAbsoluteImagePath('filetypes/text-calendar.svg'));

		if ($location) {
			$template->addBodyListItem($location, $l10n->t('Where:'),
				$this->getAbsoluteImagePath('filetypes/location.svg'));
		}
		if ($description) {
			$template->addBodyListItem((string)$description, $l10n->t('Description:'),
				$this->getAbsoluteImagePath('filetypes/text.svg'));
		}
		if ($url) {
			$template->addBodyListItem((string)$url, $l10n->t('Link:'),
				$this->getAbsoluteImagePath('filetypes/link.svg'));
		}
    }
    
    /**
	 * @param string $path
	 * @return string
	 */
	private function getAbsoluteImagePath($path) {
		return $this->urlGenerator->getAbsoluteURL(
			$this->urlGenerator->imagePath('core', $path)
		);
	}
}