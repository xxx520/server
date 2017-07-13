<?php
/**
 * @copyright Copyright (c) 2016, ownCloud, Inc.
 * @copyright Copyright (c) 2017, Georg Ehrke
 *
 * @author Georg Ehrke <oc.list@georgehrke.com>
 * @author Joas Schilling <coding@schilljs.com>
 * @author Morris Jobke <hey@morrisjobke.de>
 * @author Thomas Müller <thomas.mueller@tmit.eu>
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

use OC\Mail\Mailer;
use OCA\DAV\CalDAV\Reminder\EmailNotification;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\Defaults;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;
use OCP\Mail\IAttachment;
use OCP\Mail\IEMailTemplate;
use OCP\Mail\IMailer;
use OCP\Mail\IMessage;
use OCP\Security\ISecureRandom;
use Sabre\VObject\Component\VCalendar;
use Sabre\VObject\Component\VEvent;
use Test\TestCase;

class EmailNotificationTest extends TestCase {

	public function testDelivery() {
		$mailMessage = $this->createMock(IMessage::class);
		$mailMessage->method('setFrom')->willReturn($mailMessage);
		$mailMessage->method('setReplyTo')->willReturn($mailMessage);
		$mailMessage->method('setTo')->willReturn($mailMessage);
		/** @var Mailer | \PHPUnit_Framework_MockObject_MockObject $mailer */
		$mailer = $this->getMockBuilder(IMailer::class)->disableOriginalConstructor()->getMock();
		$emailTemplate = $this->createMock(IEMailTemplate::class);
		$emailAttachment = $this->createMock(IAttachment::class);
		$mailer->method('createEMailTemplate')->willReturn($emailTemplate);
		$mailer->method('createMessage')->willReturn($mailMessage);
		$mailer->method('createAttachment')->willReturn($emailAttachment);
		$mailer->expects($this->once())->method('send');
		/** @var ILogger | \PHPUnit_Framework_MockObject_MockObject $logger */
		$logger = $this->getMockBuilder(ILogger::class)->disableOriginalConstructor()->getMock();
		/** @var IConfig | \PHPUnit_Framework_MockObject_MockObject $config */
		$config = $this->createMock(IConfig::class);
		$l10n = $this->createMock(IL10N::class);
		/** @var IFactory | \PHPUnit_Framework_MockObject_MockObject $l10nFactory */
		$l10nFactory = $this->createMock(IFactory::class);
		$l10nFactory->method('get')->willReturn($l10n);
		/** @var IURLGenerator | \PHPUnit_Framework_MockObject_MockObject $urlGenerator */
		$urlGenerator = $this->createMock(IURLGenerator::class);

        $emailNotification = new EmailNotification($config, $mailer, $logger, $l10nFactory, $urlGenerator, 'user123');
        $vcalendar = new VCalendar();
		$vcalendar->add('VEVENT', [
			'SUMMARY' => 'Fellowship meeting',
			'DTSTART' => new \DateTime('2017-01-01 00:00:00') // 1483228800
		]);
        
		// $message = new Message();
		// $message->method = 'REQUEST';
		// $message->message = new VCalendar();
		// $message->message->add('VEVENT', [
		// 	'UID' => $message->uid,
		// 	'SEQUENCE' => $message->sequence,
		// 	'SUMMARY' => 'Fellowship meeting',
		// 	'DTSTART' => new \DateTime('2017-01-01 00:00:00') // 1483228800
		// ]);
		// $message->sender = 'mailto:gandalf@wiz.ard';
		// $message->recipient = 'mailto:frodo@hobb.it';

		$emailTemplate->expects($this->once())
			->method('setSubject')
			->with('Event: Fellowship meeting');
		$mailMessage->expects($this->once())
			->method('setTo')
			->with(['frodo@hobb.it' => 'frodo']);

        $emailNotification->sendEmail($vcalendar, 'frodo', 'frodo@hobb.it');
    }
}