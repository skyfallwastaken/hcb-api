import { json } from '@sveltejs/kit';
import { getValidTokenResponse } from '$lib/server/oauth';
import { db } from '$lib/server/db/index';
import { app, auditLog, type AuditLog, type App } from '$lib/server/db/schema';
import { env } from '$env/dynamic/private';
import micromatch from 'micromatch';
import type { RequestEvent } from './$types';
import { eq, and } from 'drizzle-orm';
import { sha256 } from '$lib/utils';

// Types
interface PermissionCheck {
	allowed: boolean;
	required?: string;
	error?: string;
}

// Constants
// routes no app may call, regardless of permissions
const BLOCKED_ROUTES = [
	// revokes the token making the request, which is HCB-API's shared OAuth token,
	// so one app could break every other app
	'POST /user/revoke'
] as const;

const MONEY_MOVEMENT_ROUTES = [
	'POST /organizations/*/card_grants',
	'POST /card_grants/*/activate',
	'POST /card_grants/*/topup',
	'POST /card_grants/*/withdraw',
	'POST /card_grants/*/cancel',
	'POST /organizations/*/transfers',
	'POST /ach_transfers',
	'POST /checks',
	'POST /wires'
] as const;

const CARD_ACCESS_ROUTES = [
	'GET /user/cards',
	'GET /organizations/*/cards',
	'POST /cards',
	'GET /cards/card_designs',
	'POST /cards/freeze',
	'POST /cards/defrost',
	'POST /cards/activate',
	'GET /cards/*',
	'PUT /cards/*',
	'PATCH /cards/*',
	'POST /cards/*/cancel',
	'GET /cards/*/transactions',
	'GET /cards/*/ephemeral_keys',

	'GET /user/card_grants',
	'GET /organizations/*/card_grants',
	'POST /organizations/*/card_grants',
	'GET /card_grants/*',
	'PUT /card_grants/*',
	'PATCH /card_grants/*',
	'POST /card_grants/*/activate',
	'POST /card_grants/*/topup',
	'POST /card_grants/*/withdraw',
	'POST /card_grants/*/cancel',
	'GET /card_grants/*/transactions'
] as const;

const FUNDRAISING_ROUTES = [
	'POST /invoices',
	'POST /organizations/*/donations',
	'POST /organizations/*/donations/*/payment_intent',
	'POST /sponsors',
	'POST /check_deposits',
	'GET /stripe_terminal_connection_token'
] as const;

const BOOKKEEPING_ROUTES = [
	'POST /comments',
	'POST /organizations/*/transactions/*/comments',
	'POST /receipts',
	'DELETE /receipts/*',
	'PUT /organizations/*/transactions/*',
	'PATCH /organizations/*/transactions/*',
	'POST /transactions/*/mark_no_receipt',
	'POST /tags',
	'DELETE /tags/*'
] as const;

const ORG_ADMIN_ROUTES = [
	'POST /organizations/*/sub_organizations',
	'POST /organizations/*/invitations',
	'DELETE /organizations/*/invitations/*',
	'POST /user/invitations/*/accept',
	'POST /user/invitations/*/reject',
	'POST /organizer_positions/*/removal_request'
] as const;

const VIEW_FINANCIALS_ROUTES = [
	'GET /organizations/*',
	'GET /organizations/*/balance_by_date',
	'GET /organizations/*/transactions',
	'GET /organizations/*/transactions/*',
	'GET /organizations/*/transactions/*/receipts',
	'GET /organizations/*/transactions/*/comments',
	'GET /organizations/*/transactions/*/memo_suggestions',
	'GET /transactions/*',
	'GET /user/transactions/missing_receipt',

	'GET /invoices',
	'GET /invoices/*',
	'GET /checks',
	'GET /checks/*',
	'GET /sponsors',
	'GET /sponsors/*',
	'GET /check_deposits',
	'GET /check_deposits/*',
	'GET /wires',
	'GET /wires/*',
	'GET /donations',
	'GET /donations/*',
	'GET /receipts',
	'GET /comments',
	'GET /tags',
	'GET /tags/*'
] as const;

const DATA_MUTATION_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

const HEADERS_TO_EXCLUDE = [
	'authorization', // we're setting our own!
	'host', // results in SSL errors
	'accept-encoding', // prevent compressed upstream responses
	'x-idempotency-key'
] as const;

const HEADERS_TO_REDACT = ['authorization'] as const;

function checkPermissions(method: string, path: string, app: App): PermissionCheck {
	const route = `${method} ${path}`;

	if (micromatch.isMatch(route, BLOCKED_ROUTES)) {
		return { allowed: false, error: 'This endpoint is not available through HCB-API' };
	}

	if (!app.allowMoneyMovement && micromatch.isMatch(route, MONEY_MOVEMENT_ROUTES)) {
		return { allowed: false, required: 'allowMoneyMovement' };
	}

	if (!app.allowCardAccess && micromatch.isMatch(route, CARD_ACCESS_ROUTES)) {
		return { allowed: false, required: 'allowCardAccess' };
	}

	if (!app.allowFundraising && micromatch.isMatch(route, FUNDRAISING_ROUTES)) {
		return { allowed: false, required: 'allowFundraising' };
	}

	if (!app.allowBookkeeping && micromatch.isMatch(route, BOOKKEEPING_ROUTES)) {
		return { allowed: false, required: 'allowBookkeeping' };
	}

	if (!app.allowOrgAdmin && micromatch.isMatch(route, ORG_ADMIN_ROUTES)) {
		return { allowed: false, required: 'allowOrgAdmin' };
	}

	if (!app.allowViewFinancials && micromatch.isMatch(route, VIEW_FINANCIALS_ROUTES)) {
		return { allowed: false, required: 'allowViewFinancials' };
	}

	return { allowed: true };
}

export const GET = handleProxyRequest;
export const POST = handleProxyRequest;
export const PUT = handleProxyRequest;
export const DELETE = handleProxyRequest;
export const PATCH = handleProxyRequest;

async function handleProxyRequest({ request, url, getClientAddress }: RequestEvent) {
	const authHeader = request.headers.get('Authorization');
	const bearer = authHeader?.replace('Bearer ', '');
	const method = request.method;
	const userIp = getClientAddress();
	const targetPath = url.pathname.replace('/api/v4', '');
	const idempotencyKey = request.headers.get('X-Idempotency-Key');

	if (!bearer) {
		return json({ error: 'Missing Authorization header' }, { status: 401 });
	}

	// do we have a valid app for this key?
	const [validApp] = await db
		.select()
		.from(app)
		.where(eq(app.apiKeyHash, await sha256(bearer)));

	if (!validApp) {
		return json({ error: 'Invalid API key' }, { status: 401 });
	}

	const routePath = canonicalRoutePath(targetPath);
	if (routePath === null) {
		return json({ error: 'Malformed request path' }, { status: 400 });
	}

	const { bytes: requestBytes, text: requestBody } = await safeReadRequestBody(request);

	if (hasMethodOverride(request, requestBody)) {
		return json(
			{ error: 'Method overrides are not supported, send the real HTTP method instead' },
			{ status: 400 }
		);
	}

	// is someone being a naughty boy? let's find out!
	// Rails routes HEAD requests to GET actions
	const routeMethod = method === 'HEAD' ? 'GET' : method;
	const permissionCheck = checkPermissions(routeMethod, routePath, validApp);
	if (!permissionCheck.allowed) {
		return json(
			{
				error: permissionCheck.error ?? 'Insufficient permissions',
				required: permissionCheck.required
			},
			{ status: 403 }
		);
	}

	// prepare request data for audit logging.
	const filteredRequestHeaders = replaceHeaders(request.headers, HEADERS_TO_REDACT, '[REDACTED]');

	const auditResult = await handleIdempotency(
		validApp.id,
		request,
		requestBody,
		filteredRequestHeaders,
		targetPath,
		userIp,
		idempotencyKey
	);

	if (auditResult.response) {
		return auditResult.response;
	}

	const auditLogEntry = auditResult.auditLogEntry;

	if (!env.HCB_CLIENT_ID) {
		return json({ error: 'HCB_CLIENT_ID not configured' }, { status: 500 });
	}

	const response = await makeUpstreamRequest(request, method, targetPath, url.search, requestBytes);
	const responseText = await safeReadResponseBody(response);

	if (auditLogEntry) {
		await updateAuditLog(auditLogEntry.id, response, responseText);
	} else {
		// fire and forget for non-idempotent requests!
		createCompleteAuditLog(
			validApp.id,
			request,
			requestBody,
			filteredRequestHeaders,
			response,
			responseText,
			targetPath,
			userIp
		).catch((error) => {
			console.error('Failed to insert audit log:', error);
		});
	}

	// these headers can cause issues with reverse proxies (e.g. cloudflare)
	const forwardHeaders = excludeHeaders(response.headers, ['content-type', 'content-encoding']);
	forwardHeaders.set('Content-Type', 'application/json; charset=utf-8');
	return new Response(responseText, {
		status: response.status,
		statusText: response.statusText,
		headers: forwardHeaders
	});
}

// helper functions!

// The path we forward is routed by HCB's Rails app, which treats `/user/revoke/`,
// `//user//revoke` and `/user/revoke.json` as `/user/revoke`. Permission checks
// need to see that same route. Rails doesn't decode `%xx` before routing, but we
// decode anyway so a decoding layer in front of HCB can't open a bypass.
// Returns null for paths we refuse to proxy.
function canonicalRoutePath(path: string): string | null {
	// an encoded slash would make our segments differ from Rails' segments
	if (/%2f|%5c/i.test(path)) return null;

	let decoded: string;
	try {
		decoded = decodeURIComponent(path);
	} catch {
		return null;
	}

	const canonical = `/${decoded}`
		.replace(/\/+/g, '/')
		.replace(/\/$/, '')
		// Rails' optional `(.:format)` suffix
		.replace(/\.[^/.]*$/, '')
		.replace(/\/$/, '');

	return canonical || '/';
}

// HCB runs Rack::MethodOverride, which turns a POST into any other method via the
// `X-HTTP-Method-Override` header or a `_method` form field. Allowing that would let
// e.g. `POST /user/cards` act as `GET /user/cards` and skip permission checks.
function hasMethodOverride(request: Request, body: string): boolean {
	if (request.method !== 'POST') return false;
	if (request.headers.has('X-HTTP-Method-Override')) return true;

	// Rack parses the body as a form when it has no content type or a form/multipart one
	const mediaType = request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase();
	if (mediaType?.startsWith('multipart/')) {
		return /content-disposition:[^\r\n]*name\*?=[^\r\n]*_method/i.test(body);
	}
	if (!mediaType || mediaType === 'application/x-www-form-urlencoded') {
		return [...new URLSearchParams(body).keys()].some((key) => key.startsWith('_method'));
	}

	return false;
}

// `bytes` is forwarded to HCB unchanged, so binary uploads like receipts survive.
// `text` is for audit logs and idempotency comparisons.
async function safeReadRequestBody(
	request: Request
): Promise<{ bytes: ArrayBuffer; text: string }> {
	try {
		const bytes = await request.arrayBuffer();
		return { bytes, text: new TextDecoder().decode(bytes).trim() };
	} catch (error) {
		console.warn('Could not read request body:', error);
		return { bytes: new ArrayBuffer(0), text: '' };
	}
}

async function safeReadResponseBody(response: Response): Promise<string | null> {
	try {
		const responseClone = response.clone();
		return await responseClone.text();
	} catch (error) {
		console.warn('Could not read response body for audit logging:', error);
		return null;
	}
}

async function makeUpstreamRequest(
	request: Request,
	method: string,
	targetPath: string,
	search: string,
	requestBody: ArrayBuffer
): Promise<Response> {
	const tokenResponse = await getValidTokenResponse(env.HCB_CLIENT_ID!);
	const targetUrl = `https://hcb.hackclub.com/api/v4${targetPath}${search}`;

	const proxyHeaders = excludeHeaders(request.headers, HEADERS_TO_EXCLUDE);
	proxyHeaders.set('Authorization', `Bearer ${tokenResponse.access_token}`);
	proxyHeaders.set('User-Agent', 'HCB-Mobile');

	return fetch(targetUrl, {
		method,
		headers: proxyHeaders,
		body: method !== 'GET' && method !== 'HEAD' ? requestBody : null
	});
}

async function createInitialAuditLog(
	appId: string,
	request: Request,
	requestBody: string,
	filteredRequestHeaders: Headers,
	targetPath: string,
	userIp: string
): Promise<AuditLog> {
	const [auditLogEntry] = await db
		.insert(auditLog)
		.values({
			appId,
			method: request.method,
			path: targetPath,
			userIp,
			requestHeaders: JSON.stringify(Object.fromEntries(filteredRequestHeaders)),
			requestBody,
			responseStatus: 0,
			responseHeaders: '{}',
			responseBody: null,
			idempotencyKey: request.headers.get('X-Idempotency-Key') || undefined
		})
		.returning();

	return auditLogEntry;
}

async function createCompleteAuditLog(
	appId: string,
	request: Request,
	requestBody: string,
	filteredRequestHeaders: Headers,
	response: Response,
	responseText: string | null,
	targetPath: string,
	userIp: string
): Promise<void> {
	await db.insert(auditLog).values({
		appId,
		method: request.method,
		path: targetPath,
		userIp,
		requestHeaders: JSON.stringify(Object.fromEntries(filteredRequestHeaders)),
		requestBody,
		responseStatus: response.status,
		responseHeaders: JSON.stringify(Object.fromEntries(response.headers)),
		responseBody: responseText,
		idempotencyKey: request.headers.get('X-Idempotency-Key') || undefined
	});
}

async function updateAuditLog(
	id: string,
	response: Response,
	responseText: string | null
): Promise<void> {
	await db
		.update(auditLog)
		.set({
			responseStatus: response.status,
			responseHeaders: JSON.stringify(Object.fromEntries(response.headers)),
			responseBody: responseText
		})
		.where(eq(auditLog.id, id));
}

async function handleIdempotency(
	appId: string,
	request: Request,
	requestBody: string,
	filteredRequestHeaders: Headers,
	targetPath: string,
	userIp: string,
	idempotencyKey: string | null
): Promise<{ auditLogEntry: AuditLog | null; response?: Response }> {
	if (!idempotencyKey || !DATA_MUTATION_METHODS.includes(request.method as any)) {
		return { auditLogEntry: null };
	}

	try {
		const auditLogEntry = await createInitialAuditLog(
			appId,
			request,
			requestBody,
			filteredRequestHeaders,
			targetPath,
			userIp
		);
		return { auditLogEntry };
	} catch (error) {
		const existingLog = await checkIdempotencyKeyCollision(appId, idempotencyKey);

		if (existingLog) {
			const response = handleIdempotencyCollision(existingLog, requestBody);
			return { auditLogEntry: null, response };
		}

		return {
			auditLogEntry: null,
			response: json({ error: `Failed to create initial audit log: ${error}` }, { status: 500 })
		};
	}
}

function handleIdempotencyCollision(existingLog: AuditLog, requestBody: string): Response {
	if (existingLog.requestBody !== requestBody) {
		return json({ error: 'Idempotency key reused with different request data' }, { status: 409 });
	}

	if (existingLog.responseStatus === 0) {
		return json(
			{ error: 'Request with this idempotency key is still being processed' },
			{ status: 409 }
		);
	}

	const originalHeaders = JSON.parse(existingLog.responseHeaders || '{}');
	return new Response(existingLog.responseBody, {
		status: existingLog.responseStatus,
		headers: originalHeaders
	});
}

async function checkIdempotencyKeyCollision(
	appId: string,
	idempotencyKey: string
): Promise<AuditLog | null> {
	const [existingLog] = await db
		.select()
		.from(auditLog)
		.where(and(eq(auditLog.appId, appId), eq(auditLog.idempotencyKey, idempotencyKey)))
		.limit(1);

	return existingLog || null;
}

function excludeHeaders(headers: Headers, exclusions: readonly string[]): Headers {
	const result = new Headers();
	headers.forEach((value, key) => {
		if (!exclusions.includes(key.toLowerCase())) {
			result.set(key, value);
		}
	});
	return result;
}

function replaceHeaders(
	headers: Headers,
	toBeReplaced: readonly string[],
	replaceWith: string
): Headers {
	const result = new Headers();
	headers.forEach((value, key) => {
		result.set(key, toBeReplaced.includes(key.toLowerCase()) ? replaceWith : value);
	});
	return result;
}
