import adapter from 'svelte-adapter-bun';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	// Consult https://svelte.dev/docs/kit/integrations
	// for more information about preprocessors
	preprocess: vitePreprocess(),

	kit: {
		// adapter-auto only supports some environments, see https://svelte.dev/docs/kit/adapter-auto for a list.
		// If your environment is not supported, or you settled on a specific environment, switch out the adapter.
		// See https://svelte.dev/docs/kit/adapters for more information about adapters.
		adapter: adapter(),
		// SvelteKit's origin check rejects form, multipart and text/plain requests from
		// API clients, which authenticate with a bearer token rather than cookies.
		// src/hooks.server.ts applies the same check to every route except the API.
		csrf: {
			trustedOrigins: ['*']
		}
	}
};

export default config;
