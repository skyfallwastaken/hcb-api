import { text, type Handle } from '@sveltejs/kit';
import { dev } from '$app/environment';

// SvelteKit's built-in CSRF check is turned off in svelte.config.js so the API proxy
// accepts form and multipart requests (e.g. receipt uploads). This re-applies the same
// check to everything else, i.e. the cookie-authenticated dashboard.

const FORM_CONTENT_TYPES = [
	'application/x-www-form-urlencoded',
	'multipart/form-data',
	'text/plain'
] as const;

const UNSAFE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

function isApiRoute(url: URL): boolean {
	return url.pathname === '/api/v4' || url.pathname.startsWith('/api/v4/');
}

function isCrossSiteFormSubmission(request: Request, url: URL): boolean {
	const mediaType = request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase();

	return (
		FORM_CONTENT_TYPES.some((type) => type === mediaType) &&
		UNSAFE_METHODS.some((method) => method === request.method) &&
		request.headers.get('Origin') !== url.origin
	);
}

export const handle: Handle = async ({ event, resolve }) => {
	const { request, url } = event;

	// matches SvelteKit, which skips this check in dev
	if (!dev && !isApiRoute(url) && isCrossSiteFormSubmission(request, url)) {
		return text(`Cross-site ${request.method} form submissions are forbidden`, { status: 403 });
	}

	return resolve(event);
};
