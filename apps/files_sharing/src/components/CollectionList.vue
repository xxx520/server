<!--
  - @copyright Copyright (c) 2019 Julius Härtl <jus@bitgrid.net>
  -
  - @author Julius Härtl <jus@bitgrid.net>
  -
  - @license GNU AGPL version 3 or any later version
  -
  - This program is free software: you can redistribute it and/or modify
  - it under the terms of the GNU Affero General Public License as
  - published by the Free Software Foundation, either version 3 of the
  - License, or (at your option) any later version.
  -
  - This program is distributed in the hope that it will be useful,
  - but WITHOUT ANY WARRANTY; without even the implied warranty of
  - MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  - GNU Affero General Public License for more details.
  -
  - You should have received a copy of the GNU Affero General Public License
  - along with this program. If not, see <http://www.gnu.org/licenses/>.
  -
  -->

<template>
	<ul id="shareWithList" class="shareWithList" v-if="collections">
		<li @click="showSelect">
			<div class="avatar"><span class="icon-category-integration icon-white"></span></div>
			<multiselect v-model="value" :options="options" :placeholder="placeholder" tag-placeholder="Create a new collection" ref="select" @select="select" @search-change="search" label="title" track-by="title" :reset-after="true" :limit="5">
				<template slot="singleLabel" slot-scope="props">
					<span class="option__desc">
						<span class="option__title">{{ props.option.title }}</span>
					</span>
				</template>
				<template slot="option" slot-scope="props">
					<span class="option__wrapper">
						<span v-if="props.option.class" :class="props.option.class" class="avatar"></span>
						<avatar v-else :displayName="props.option.title" :allowPlaceholder="true"></avatar>
						<span class="option__title">{{ props.option.title }}</span>
					</span>
				</template>
			</multiselect>
		</li>
		<collection-list-item v-for="collection in collections" :collection="collection" :key="collection.id" />
	</ul>
</template>

<style lang="scss" scoped>
	.multiselect {
		width: 100%;
		margin-left: 3px;
	}
	span.avatar {
		padding: 16px;
		display: block;
		background-repeat: no-repeat;
		background-position: center;
		opacity: 0.7;
		&:hover {
			opacity: 1;
		}
	}

	/** TODO provide white icon in core */
	.icon-category-integration.icon-white {
		filter: invert(100%);
		padding: 16px;
		display: block;
		background-repeat: no-repeat;
		background-position: center;
	}

	.option__wrapper {
		display: flex;
		.avatar {
			display: block;
			background-color: var(--color-background-darker) !important;
		}
		.option__title {
			padding: 4px;
		}
	}

</style>
<style lang="scss">
	/** TODO check why this doesn't work when scoped */
	.shareWithList .multiselect:not(.multiselect--active ) .multiselect__tags {
		border: none !important;
		input::placeholder {
			color: var(--color-main-text);
		}
	}
</style>

<script>
	import { Multiselect, Avatar } from 'nextcloud-vue';
	import CollectionListItem from '../components/CollectionListItem';
	import axios from 'nextcloud-axios';

	const METHOD_CREATE_COLLECTION = 0;
	const METHOD_ADD_TO_COLLECTION = 1;
	export default {
		name: 'CollectionList',
		components: {
			CollectionListItem,
			Avatar,
			Multiselect: Multiselect,
		},
		props: {
			'type': {
				type: String,
				default: ''
			}
		},
		data() {
			return {
				selectIsOpen: false,
				generatingCodes: false,
				codes: undefined,
				value: null,
				model: {},
				collections: null,
				searchCollections: []
			};
		},
		mounted() {
			let resourceId = this.$root.model.id
			/** TODO move to service */
			const resourceBase = OC.linkToOCS(`collaboration/resources/${this.type}`);
			axios.get(`${resourceBase}${resourceId}?format=json`, {
				headers: {
					'OCS-APIRequest': true,
					'Content-Type': 'application/json; charset=UTF-8'
				}
			}).then((response) => {
				this.collections = response.data.ocs.data
			});
		},
		computed: {
			placeholder() {
				return t('files_sharing', 'Add to a collection');
			},
			options() {
				let options = [];
				let types = window.OCP.Collaboration.getTypes().sort();
				for(let type in types) {
					options.push({
						method: METHOD_CREATE_COLLECTION,
						type: types[type],
						title: window.OCP.Collaboration.getLabel(types[type]),
						class: window.OCP.Collaboration.getIcon(types[type]),
						action: () => window.OCP.Collaboration.trigger(types[type])
					})
				}
				for(let index in this.searchCollections) {
					options.push({
						method: METHOD_ADD_TO_COLLECTION,
						title: this.searchCollections[index].name,
						collectionId: this.searchCollections[index].id
					})
				}
				return options;
			}
		},
		created: function() {
		},
		methods: {
			select(selectedOption, id) {
				if (selectedOption.method === METHOD_CREATE_COLLECTION) {
					selectedOption.action().then((id) => {
						console.log('Create a new collection with')
						console.log('This file ', this.$root.model.id)
						console.log('Selected resource ', selectedOption.type, id)
						this.createCollection(this.$root.model.id, selectedOption.type, id)
					}).catch((e) => {
						console.error('No resource selected');
					});
				}

				if (selectedOption.method === METHOD_ADD_TO_COLLECTION) {
					this.addResourceToCollection(selectedOption.collectionId, this.type, this.$root.model.id)
				}
			},
			search(query) {
				const searchBase = OC.linkToOCS(`collaboration/resources/collections/search`);
				axios.get(`${searchBase}%25${query}%25?format=json`, {
					headers: {
						'OCS-APIRequest': true,
						'Content-Type': 'application/json; charset=UTF-8'
					}
				}).then((response) => {
					this.searchCollections = response.data.ocs.data
				});
			},
			showSelect() {
				this.selectIsOpen = true
				this.$refs.select.$el.focus()
			},
			hideSelect() {
				this.selectIsOpen = false
			},
			isVueComponent(object) {
				return object._isVue
			},
			createCollection(resourceIdBase, resourceType, resourceId) {
				/** TODO move to service */
				const resourceBase = OC.linkToOCS(`collaboration/resources/files`, 2);
				axios.post(`${resourceBase}${resourceIdBase}?format=json`, {
					name: this.$root.model.name
				}, {
					headers: {
						'OCS-APIRequest': true,
						'Content-Type': 'application/json; charset=UTF-8'
					}
				}).then((response) => {
					let newCollection = response.data.ocs.data
					console.log('Add new collection', newCollection)
					this.collections.push(newCollection)
					this.addResourceToCollection(newCollection.id, resourceType.toString(), resourceId.toString())
				});
			},
			addResourceToCollection(collectionId, resourceType, resourceId) {
				resourceId = '' + resourceId;
				/** TODO move to service */
				const resourceBase = OC.linkToOCS(`collaboration/resources/collections`, 2);
				return axios.post(`${resourceBase}${collectionId}?format=json`, {
					resourceType,
					resourceId
				}, {
					headers: {
						'OCS-APIRequest': true,
						'Content-Type': 'application/json; charset=UTF-8'
					}
				}).then((response) => {
					console.log('Add new collection', response.data.ocs.data)
					let collection = this.collections.find((_item) => _item.id === collectionId)
					if (collection) {
						this.collections.find((_item) => _item.id === collectionId).resources = response.data.ocs.data.resources
					} else {
						this.collections.push(response.data.ocs.data)
					}
				});
			}
		}
	}
</script>
