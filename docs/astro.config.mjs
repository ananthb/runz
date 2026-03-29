import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
	integrations: [
		starlight({
			title: 'runz',
			description: 'OCI container runtime and library in Zig',
			customCss: ['./src/styles/custom.css'],
            disable404Route: true,
			social: {
				github: 'https://github.com/ananthb/runz',
			},
			sidebar: [
				{
					label: 'Guides',
					items: [
						{ label: 'Getting Started', link: '/guides/getting-started/' },
						{ label: 'Architecture', link: '/guides/architecture/' },
					],
				},
				{
					label: 'Examples',
					autogenerate: { directory: 'examples' },
				},
				{
					label: 'API Reference',
					link: '/api/index.html',
                    attrs: { target: '_blank' },
				},
			],
		}),
	],
});
