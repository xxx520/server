/*
 * @copyright Copyright (c) 2019 Julius Härtl <jus@bitgrid.net>
 *
 * @author Julius Härtl <jus@bitgrid.net>
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

import axios from 'nextcloud-axios';
import Vuex from 'vuex';

const store = new Vuex.Store({
	state: {
		collections: []
	},
	mutations: {
		addCollection (state, collection) {
			state.collections.push(collection)
		},
		removeCollection (state, collection) {
			state.collections = state.collections.filter(item => item.id !== collection.id)
		}
	}
})

class Service {
	constructor() {
		this.http = axios;
		this.baseUrl = OC.linkToOCS(`collaboration/resources`);
	}

	listCollection(collectionId) {
		return this.http.get(`${this.baseUrl}collections/${collectionId}`)
	}

	renameCollection(collectionId, collectionName) {
		const resourceBase = OC.linkToOCS(`collaboration/resources/collections`, 2);
		return this.http.put(`${resourceBase}${collectionId}?format=json`, {
			collectionName
		})
	}

	addResource(collectionId, resource) {
		return this.http.post(`/collections/${collectionId}`)
	}

	removeResource(collectionId, resourceType, resourceId) {
		return this.http.delete(`${this.baseUrl}/collections/${collectionId}`, { params: { resourceType, resourceId } } )
	}

	createCollectionOnResource(resourceType, resourceId) {
		return this.http.post(`/${resourceType}/${resourceId}`)
	}

	getCollectionByResource(resourceType, resourceId) {
		return this.http.get(`/${resourceType}/${resourceId}`)
	}

	getProviders() {

	}

	search() {

	}
}

export default new Service;
export { store };
