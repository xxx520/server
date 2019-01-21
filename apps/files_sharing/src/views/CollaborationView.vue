<template>
	<div>
		<ul id="shareWithList" class="shareWithList">
			<li @click="showSelect">
				<div class="avatar"><span class="icon-category-integration icon-white"></span></div>
				<multiselect v-model="value" :options="options" :placeholder="placeholder" tag-placeholder="Create a new collection" ref="select" @select="select" label="title" track-by="title" :reset-after="true">
					<template slot="singleLabel" slot-scope="props">
						<span class="option__desc">
							<span class="option__title">{{ props.option.title }}</span></span>
					</template>
					<template slot="option" slot-scope="props">
						<span class="option__wrapper">
							<span :class="props.option.class" class="avatar"></span>
							<span class="option__title">{{ props.option.title }}</span>
						</span>
					</template>
				</multiselect>
			</li>
			<resource-list-item></resource-list-item>
			<resource-list-item></resource-list-item>
			<resource-list-item></resource-list-item>
		</ul>
		<pre>Vue component file model: {{ this.$root.model.name }} </pre>

	</div>
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
	import { Multiselect } from 'nextcloud-vue';
	import ResourceListItem from '../components/ResourceListItem';
	import axios from 'nextcloud-axios';

	export default {
		name: 'CollaborationView',
		components: {
			ResourceListItem,
			Multiselect: Multiselect,
		},
		data() {
			return {
				selectIsOpen: false,
				generatingCodes: false,
				codes: undefined,
				value: null,
				model: {}
			};
		},
		mounted() {
			axios.get(OC.linkToOCS(`/collaboration/resources/${resourceType}/${resourceId}`)).then((response) => {
				console.log(response)
			});
		},
		computed: {
			placeholder() {
				return t('files_sharing', 'Add to a collection');
			},
			options() {
				let options = [];
				let types = window.Collaboration.getTypes();
				for(let type in types) {
					options.push({
						type: types[type],
						title: window.Collaboration.getLabel(types[type]),
						class: window.Collaboration.getIcon(types[type]),
						action: () => window.Collaboration.trigger(types[type])
					})
				}
				return options;
			}
		},
		created: function() {
		},
		methods: {
			select(selectedOption, id) {
				selectedOption.action().then((id) => {
					console.log('Create a new collection with')
					console.log('This file ', this.$root.model.id)
					console.log('Selected resource ', selectedOption.type, id)
				}).catch((e) => {
					console.error('No resource selected');
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
			}
		}
	}
</script>
