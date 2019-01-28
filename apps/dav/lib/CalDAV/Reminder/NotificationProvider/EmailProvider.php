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

namespace OCA\DAV\CalDAV\Reminder\NotificationProvider;

use OCA\DAV\CalDAV\Reminder\AbstractNotificationProvider;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IURLGenerator;
use OCP\L10N\IFactory as L10NFactory;
use OCP\Mail\IEMailTemplate;
use OCP\Mail\IMailer;
use OCP\IUser;
use Sabre\VObject\Component\VCalendar;

class EmailProvider extends AbstractNotificationProvider
{
	/** @var IConfig */
	private $config;

	/** @var IMailer */
	private $mailer;

	/**
	 * @param IConfig $config
	 * @param IMailer $mailer
	 * @param ILogger $logger
	 * @param L10NFactory $l10nFactory
	 * @param IUrlGenerator $urlGenerator
	 * @param IDBConnection $db
	 */
	public function __construct(IConfig $config, IMailer $mailer, ILogger $logger,
								L10NFactory $l10nFactory,
								IURLGenerator $urlGenerator) {
		parent::__construct($logger, $l10nFactory, $urlGenerator);
		$this->config = $config;
		$this->mailer = $mailer;
	}

	/**
	 * Send notification
	 *
	 * @param VCalendar $vcalendar
	 * @param IUser $user
	 * @return void
	 */
	public function send(VCalendar $vcalendar, IUser $user): void
	{
		$this->setLangForUser($user);
		$event = $this->extractEventDetails($vcalendar);
		$fromEMail = \OCP\Util::getDefaultEmailAddress('invitations-noreply');

		if ($user->getEMailAddress() === null) {
			return;
		}

		$message = $this->mailer->createMessage()
			->setFrom([$fromEMail => 'Nextcloud']) // TODO : reply me
			// ->setReplyTo([$sender => $senderName])
			->setTo([$user->getEMailAddress() => $user->getDisplayName()]);

		$template = $this->mailer->createEMailTemplate('dav.calendarReminder', $event);
		$template->addHeader();

		$this->addSubjectAndHeading($template, $event['title']);
		$this->addBulletList($template, $event);

		$template->addFooter();
		$message->useTemplate($template);

		$attachment = $this->mailer->createAttachment(
			$vcalendar->serialize(),
			$event['uid'].'.ics',// TODO(leon): Make file name unique, e.g. add event id
			'text/calendar'
		);
		$message->attach($attachment);
		var_dump('Sending email');

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
	 * @param IEMailTemplate $template
	 * @param string $summary
	 */
	private function addSubjectAndHeading(IEMailTemplate $template, string $summary)
	{
		$template->setSubject('Event: ' . $summary);
		$template->addHeading($this->l10n->t('Don\'t forget to go to %1$s ', [$summary]));
	}

    /**
	 * @param IEMailTemplate $template
	 * @param array $eventData
	 */
	private function addBulletList(IEMailTemplate $template, array $eventData) {
		$template->addBodyListItem($eventData['when'], $this->l10n->t('When:'),
			$this->getAbsoluteImagePath('filetypes/text-calendar.svg'));

		if ($eventData['location']) {
			$template->addBodyListItem((string) $eventData['location'], $this->l10n->t('Where:'),
				$this->getAbsoluteImagePath('filetypes/location.svg'));
		}
		if ($eventData['description']) {
			$template->addBodyListItem((string) $eventData['description'], $this->l10n->t('Description:'),
				$this->getAbsoluteImagePath('filetypes/text.svg'));
		}
		if ($eventData['url']) {
			$template->addBodyListItem((string) $eventData['url'], $this->l10n->t('Link:'),
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