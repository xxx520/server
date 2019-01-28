<?php
/**
 * @copyright Copyright (c) 2017 Thomas Citharel <tcit@tcit.fr>
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

use OCP\IDBConnection;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IUserSession;
use Sabre\VObject;
use Sabre\VObject\Component\VAlarm;
use Sabre\VObject\Reader;

/**
 * Class Backend
 *
 * @package OCA\DAV\CalDAV\Reminder
 */
class Backend {

	/** @var IGroupManager */
	protected $groupManager;

	/** @var IUserSession */
	protected $userSession;

	/** @var IDBConnection */
	protected $db;

	const ALARM_TYPES = ['AUDIO', 'EMAIL', 'DISPLAY'];

	/**
	 * @param IDBConnection $db
	 * @param IGroupManager $groupManager
	 * @param IUserSession $userSession
	 */
	public function __construct(IDBConnection $db, IGroupManager $groupManager, IUserSession $userSession) {
		$this->db = $db;
		$this->groupManager = $groupManager;
		$this->userSession = $userSession;
	}

	/**
	 * Saves reminders when a calendar object with some alarms was created/updated/deleted
	 *
	 * @param string $action
	 * @param array $calendarData
	 * @param array $shares
	 * @param array $objectData
	 * @return void
	 */
	public function onTouchCalendarObject($action, array $calendarData, array $shares, array $objectData): void
	{
		if (!isset($calendarData['principaluri'])) {
			return;
		}
		error_log('ontouchCalendarObject');

		// Always remove existing reminders for this event
		$this->cleanRemindersForEvent($objectData['calendarid'], $objectData['uri']);
		if ($action === '\OCA\DAV\CalDAV\CalDavBackend::deleteCalendarObject') {
			return;
		}

		$principal = explode('/', $calendarData['principaluri']);
		$owner = array_pop($principal);

		$users = $this->getUsersForShares($shares);
		$users[] = $this->userSession->getUser()->getUID();

		$vobject = VObject\Reader::read($objectData['calendardata']);

		foreach ($vobject->VEVENT->VALARM as $alarm) {
			if ($alarm instanceof VAlarm) {
				error_log('found an alarm');
				$type = strtoupper($alarm->ACTION->getValue());
				if (in_array($type, self::ALARM_TYPES, true)) {
					error_log('right alarm type');
					$time = $alarm->getEffectiveTriggerTime();

					foreach ($users as $user) {
						$query = $this->db->getQueryBuilder();
						error_log('inserting reminder');
						$query->insert('calendar_reminders')
							->values([
								'uid' => $query->createNamedParameter($user),
								'calendarid' => $query->createNamedParameter($objectData['calendarid']),
								'objecturi' => $query->createNamedParameter($objectData['uri']),
								'type' => $query->createNamedParameter($type),
								'notificationdate' => $query->createNamedParameter($time->getTimestamp()),
								'eventstartdate' => $query->createNamedParameter($vobject->VEVENT->DTSTART->getDateTime()->getTimestamp()),
							])->execute();
					}
				}
			}
		}
	}

	/**
	 * Get all users that have access to a given calendar
	 *
	 * @param array $shares
	 * @return string[]
	 */
	protected function getUsersForShares(array $shares): array
	{
		$users = $groups = [];
		foreach ($shares as $share) {
			$prinical = explode('/', $share['{http://owncloud.org/ns}principal']);
			if ($prinical[1] === 'users') {
				$users[] = $prinical[2];
			} else if ($prinical[1] === 'groups') {
				$groups[] = $prinical[2];
			}
		}

		if (!empty($groups)) {
			foreach ($groups as $gid) {
				$group = $this->groupManager->get($gid);
				if ($group instanceof IGroup) {
					foreach ($group->getUsers() as $user) {
						$users[] = $user->getUID();
					}
				}
			}
		}

		return array_unique($users);
	}

	/**
	 * Cleans reminders in database
	 *
	 * @param int $calendarId
	 * @param string $objectUri
	 */
	private function cleanRemindersForEvent(int $calendarId, string $objectUri): void
	{
		$query = $this->db->getQueryBuilder();

		$query->delete('calendar_reminders')
			->where($query->expr()->eq('calendarid', $query->createNamedParameter($calendarId)))
			->andWhere($query->expr()->eq('objecturi', $query->createNamedParameter($objectUri)))
			->execute();
	}

	/**
	 * Remove all reminders for a calendar
	 *
	 * @param integer $calendarId
	 * @return void
	 */
	public function cleanRemindersForCalendar(int $calendarId): void
	{
		$query = $this->db->getQueryBuilder();

		$query->delete('calendar_reminders')
			->where($query->expr()->eq('calendarid', $query->createNamedParameter($calendarId)))
			->execute();
	}

	/**
	 * Remove a reminder by it's id
	 *
	 * @param integer $reminderId
	 * @return void
	 */
	public function removeReminder(int $reminderId): void
	{
		$query = $this->db->getQueryBuilder();

		$query->delete('calendar_reminders')
			->where($query->expr()->eq('id', $query->createNamedParameter($reminderId)))
			->execute();
	}

	/**
	 * Get reminders list
	 *
	 * @return array
	 */
	// public function getReminders(): array
	// {
	// 	$query = $this->db->getQueryBuilder();
	// 	$fields = ['id', 'notificationdate'];
	// 	$result = $query->select($fields)
	// 		->from('calendar_reminders')
	// 		->execute();

	// 	$reminders = [];
	// 	while($row = $result->fetch(\PDO::FETCH_ASSOC)) {
	// 		$reminder = [
	// 			'id' => $row['id'],
	// 			'notificationdate' => $row['notificationdate']
	// 		];

	// 		$reminders[] = $reminder;

	// 	}
	// 	return $reminders;
	// }

	/**
	 * Get all reminders with a notification date before now
	 * 
	 * @return array
	 */
	public function getRemindersToProcess()
	{
		$query = $this->db->getQueryBuilder();
		$fields = ['cr.id', 'cr.calendarid', 'cr.objecturi', 'cr.type', 'cr.notificationdate', 'cr.uid', 'co.calendardata', 'c.displayname'];
		return $query->select($fields)
			->from('calendar_reminders', 'cr')
			->where($query->expr()->gte('cr.notificationdate', $query->createNamedParameter((new \DateTime())->getTimestamp())))
			->andWhere($query->expr()->gte('cr.eventstartdate', $query->createNamedParameter((new \DateTime())->getTimestamp()))) # We check that DTSTART isn't before
			->leftJoin('cr', 'calendars', 'c', $query->expr()->eq('cr.calendarid', 'c.id'))
			->leftJoin('cr', 'calendarobjects', 'co', $query->expr()->andX($query->expr()->eq('cr.calendarid', 'c.id'), $query->expr()->eq('co.uri', 'cr.objecturi')))
			->execute();
	}

	/**
	 * Get reminder with calendar and event details
	 *
	 * @param integer $id
	 * @return null|array
	 */
	// public function getReminder(int $id)
	// {
	// 	$query = $this->db->getQueryBuilder();
	// 	$fields = ['cr.id', 'cr.calendarid', 'objecturi', 'type', 'notificationdate', 'cr.uid', 'calendardata', 'displayname'];
	// 	$result = $query->select($fields)
	// 		->from('calendar_reminders', 'cr')
	// 		->where($query->expr()->eq('cr.id', $query->createNamedParameter($id)))
	// 		->leftJoin('cr', 'calendars', 'c', $query->expr()->eq('cr.calendarid', 'c.id'))
	// 		->leftJoin('cr', 'calendarobjects', 'co', $query->expr()->andX($query->expr()->eq('cr.calendarid', 'c.id'), $query->expr()->eq('co.uri', 'cr.objecturi')))
	// 		->setMaxResults(1)
	// 		->execute();

	// 	$stmt = $query->execute();

	// 	$row = $stmt->fetch(\PDO::FETCH_ASSOC);
	// 	$stmt->closeCursor();
	// 	if ($row === false) {
	// 		return null;
	// 	}

	// 	return $row;
	// }
}
