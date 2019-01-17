<template>
	<div>
		<ul id="shareWithList" class="shareWithList">
			<li @click="showSelect">
				<div class="avatar icon-category-integration icon-white"></div>
				<span class="username" title="" v-show="!selectIsOpen">{{ t('files_sharing', 'Add to a collection') }}</span>
				<multiselect v-show="selectIsOpen" v-model="value" :options="options" :placeholder="placeholder" @blur="hideSelect" :taggable="true" tag-placeholder="Create a new collection" ref="select" >
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
	}
	.icon-category-integration {
	}

	.option__wrapper {
		display: flex;
		.avatar {
			display: block;
			background-color: var(--color-background-dark) !important;
		}
		.option__title {
			padding: 4px;
		}
	}

</style>

<script>
	import { Multiselect } from 'nextcloud-vue';
	import ResourceListItem from '../components/ResourceListItem';

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
				model: {},
				options: [
					{
						title: 'Link to a file',
						class: 'icon-files'
					},
					{
						title: 'Link to a board',
						class: 'icon-deck'
					},
					{
						title: 'Link to a calendar',
						class: 'icon-calendar-dark'
					}
				]
			};
		},
		mounted() {
		},
		computed: {
			placeholder() {
				return t('files_sharing', 'Add to a collection');
			}
		},
		created: function() {
		},
		methods: {
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
