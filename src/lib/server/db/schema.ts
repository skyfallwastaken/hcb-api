import { sqliteTable, text, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core';
import { nanoid } from 'nanoid';
import { sql } from 'drizzle-orm';

export const app = sqliteTable(
	'apps',
	{
		id: text('id')
			.primaryKey()
			.$default(() => `app_${nanoid(6)}`),
		appName: text('app_name').notNull(),
		apiKeyHash: text('api_key_hash').notNull(),
		allowMoneyMovement: integer('allow_money_movement', { mode: 'boolean' })
			.notNull()
			.default(false),
		allowCardAccess: integer('allow_card_access', { mode: 'boolean' }).notNull().default(false),
		allowFundraising: integer('allow_fundraising', { mode: 'boolean' }).notNull().default(false),
		allowBookkeeping: integer('allow_bookkeeping', { mode: 'boolean' }).notNull().default(false),
		allowOrgAdmin: integer('allow_org_admin', { mode: 'boolean' }).notNull().default(false),
		allowViewFinancials: integer('allow_view_financials', { mode: 'boolean' })
			.notNull()
			.default(false)
	},
	(table) => [index('app_id_idx').on(table.id), index('app_api_key_hash_idx').on(table.apiKeyHash)]
);

export const oauthToken = sqliteTable(
	'oauth_tokens',
	{
		id: text('id')
			.primaryKey()
			.$default(() => `token_${nanoid(6)}`),
		oauthClientId: text('oauth_client_id').notNull().unique(),
		accessToken: text('access_token').notNull(),
		refreshToken: text('refresh_token').notNull(),
		createdAt: integer('created_at').notNull(),
		expiresIn: integer('expires_in').notNull(),
		expiresAt: integer('expires_at').notNull(),
		updatedAt: text('updated_at')
			.default(sql`(CURRENT_TIMESTAMP)`)
			.notNull()
	},
	(table) => [
		index('oauth_tokens_expires_at_idx').on(table.expiresAt),
		index('oauth_tokens_updated_at_idx').on(table.updatedAt),
		index('oauth_tokens_oauth_client_id_idx').on(table.oauthClientId)
	]
);

export const authConfig = sqliteTable('auth_config', {
	id: text('id')
		.primaryKey()
		.$default(() => `config_${nanoid(6)}`),
	passwordHash: text('password_hash').notNull(),
	jwtSecret: text('jwt_secret'),
	createdAt: text('created_at')
		.default(sql`(CURRENT_TIMESTAMP)`)
		.notNull(),
	updatedAt: text('updated_at')
		.default(sql`(CURRENT_TIMESTAMP)`)
		.notNull()
});

export const auditLog = sqliteTable(
	'audit_logs',
	{
		id: text('id')
			.primaryKey()
			.$default(() => `log_${nanoid(8)}`),
		appId: text('app_id')
			.notNull()
			.references(() => app.id, { onDelete: 'cascade' }),
		method: text('method').notNull(),
		path: text('path').notNull(),
		userIp: text('user_ip').notNull(),
		requestHeaders: text('request_headers').notNull(),
		requestBody: text('request_body'),
		responseStatus: integer('response_status').notNull(),
		responseHeaders: text('response_headers').notNull(),
		responseBody: text('response_body'),
		idempotencyKey: text('idempotency_key'),
		timestamp: text('timestamp')
			.default(sql`(CURRENT_TIMESTAMP)`)
			.notNull()
	},
	(table) => [
		index('audit_logs_app_id_timestamp_idx').on(table.appId, table.timestamp),
		index('audit_logs_timestamp_idx').on(table.timestamp),
		index('audit_logs_method_idx').on(table.method),
		index('audit_logs_response_status_idx').on(table.responseStatus),
		uniqueIndex('audit_logs_app_id_idempotency_key_idx').on(table.appId, table.idempotencyKey)
	]
);

export type AuditLog = typeof auditLog.$inferSelect;
export type App = typeof app.$inferSelect;
