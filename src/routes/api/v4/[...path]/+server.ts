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
}

// Constants
const MONEY_MOVEMENT_ROUTES = [
	'POST /organizations/*/card_grants',
	'POST /card_grants/*/activate',
	'POST /card_grants/*/topup',
	'POST /card_grants/*/withdraw',
	'POST /card_grants/*/cancel',
	'POST /organizations/*/transfers',
	'POST /ach_transfers',
	'POST /checks'
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
	'POST /sponsors'
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
	'DELETE /organizations/*/invitations/*'
] as const;

const VIEW_FINANCIALS_ROUTES = [
	'GET /organizations/*',
	'GET /organizations/*/balance_by_date',
	'GET /organizations/*/transactions',
	'GET /organizations/*/transactions/*',
	'GET /organizations/*/transactions/*/receipts',
	'GET /organizations/*/transactions/*/comments',
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

	// is someone being a naughty boy? let's find out!
	const permissionCheck = checkPermissions(method, targetPath, validApp);
	if (!permissionCheck.allowed) {
		return json(
			{ error: 'Insufficient permissions', required: permissionCheck.required },
			{ status: 403 }
		);
	}

	// prepare request data for audit logging.
	const requestBody = await safeReadRequestBody(request);
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

	const response = await makeUpstreamRequest(request, method, targetPath, url.search, requestBody);
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
async function safeReadRequestBody(request: Request): Promise<string> {
	try {
		const bodyText = await request.text();
		return bodyText?.trim() || '';
	} catch (error) {
		console.warn('Could not read request body for audit logging:', error);
		return '';
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
	requestBody: string
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
