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

use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IUserSession;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCA\DAV\CalDAV\CalDavBackend;
use OCA\DAV\CalDAV\Reminder\Backend as ReminderBackend;

class BackendTest extends TestCase {

    /**
     * Reminder Backend
     *
     * @var ReminderBackend
     */
    private $reminderBackend;

    public function setUp() {
		parent::setUp();

        $this->dbConnection = $this->createMock(IDBConnection::class);
        $this->groupManager = $this->createMock(IGroupManager::class);
        $this->userSession = $this->createMock(IUserSession::class);
        $this->backend = $this->createMock(CalDavBackend::class);
        $this->reminderBackend = new ReminderBackend($this->dbConnection, $this->groupManager, $this->userSession);
    }

    public function providesTouchCalendarObject()
    {
        return [
            [
                '\OCA\DAV\CalDAV\CalDavBackend::deleteCalendarObject',
                null,
                null,
                null
            ]
        ];
    }

    /**
     * @dataProvider providesTouchCalendarObject
     */
    public function testOnTouchCalendarObject($action, $calendardata, $shares, $objectdata)
    {
        
    }

    public function testCleanRemindersForEvent()
    {
        $queryBuilder = $this->createMock(IQueryBuilder::class);
        $stmt = $this->createMock(\Doctrine\DBAL\Driver\Statement::class);

        $this->dbConnection->expects($this->once())
			->method('getQueryBuilder')
			->with()
            ->will($this->returnValue($queryBuilder));

        $queryBuilder->expects($this->at(0))
			->method('delete')
			->with('calendar_reminders')
            ->will($this->returnValue($queryBuilder));

        $queryBuilder->expects($this->at(1))
			->method('where')
			->with('WHERE_CLAUSE_1')
			->will($this->returnValue($queryBuilder));
		$queryBuilder->expects($this->at(2))
			->method('andWhere')
			->with('WHERE_CLAUSE_2')
			->will($this->returnValue($queryBuilder));

		$queryBuilder->expects($this->at(3))
			->method('execute')
			->with()
            ->will($this->returnValue($stmt));
    }
}