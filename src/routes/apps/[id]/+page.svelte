<script lang="ts">
	import { page } from '$app/state';
	import PageHeader from '$lib/components/page-header.svelte';
	import { Button } from '$lib/components/ui/button';
	import {
		Card,
		CardContent,
		CardDescription,
		CardHeader,
		CardTitle
	} from '$lib/components/ui/card';
	import { Switch } from '$lib/components/ui/switch';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import Copy from '@lucide/svelte/icons/copy';
	import CheckCircle from '@lucide/svelte/icons/check-circle';
	import { superForm } from 'sveltekit-superforms';
	import { arktype } from 'sveltekit-superforms/adapters';
	import { appPermissionsSchema } from '$lib/home';
	import DeleteAppDialog from '$lib/components/apps/delete-app-dialog.svelte';
	import RegenerateApiKeyDialog from '$lib/components/apps/regenerate-api-key-dialog.svelte';

	const { app, form: formData, flash } = page.data;
	let copied = $state(false);

	async function copyApiKey(key: string) {
		try {
			await navigator.clipboard.writeText(key);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch (err) {
			console.error('Failed to copy API key:', err);
		}
	}

	const { form, enhance, submitting, tainted } = superForm(formData, {
		validators: arktype(appPermissionsSchema)
	});
</script>

<svelte:head>
	<title>{app.name} – HCB-API</title>
</svelte:head>

<PageHeader>
	<svelte:fragment slot="title">{app.name}</svelte:fragment>

	<div slot="actions" class="flex gap-2">
		<Button variant="outline" href="/apps/{app.id}/audit">View audit logs</Button>
		<RegenerateApiKeyDialog {app} data={page.data} />
		<DeleteAppDialog {app} data={page.data} />
	</div>
</PageHeader>

<form method="POST" action="?/updatePermissions" use:enhance class="px-6 pb-8">
	<input type="hidden" name="allowMoneyMovement" value={$form.allowMoneyMovement} />
	<input type="hidden" name="allowCardAccess" value={$form.allowCardAccess} />
	<input type="hidden" name="allowFundraising" value={$form.allowFundraising} />
	<input type="hidden" name="allowBookkeeping" value={$form.allowBookkeeping} />
	<input type="hidden" name="allowOrgAdmin" value={$form.allowOrgAdmin} />
	<input type="hidden" name="allowViewFinancials" value={$form.allowViewFinancials} />

	{#if flash?.data?.apiKey}
		<Card class="mb-8 sm:w-full md:w-1/2 lg:w-1/3">
			<CardHeader>
				<CardTitle>Your API key</CardTitle>
				<CardDescription>
					This is your new API key. Copy it now - you won't be able to see it again!
				</CardDescription>
			</CardHeader>
			<CardContent>
				<div class="flex items-center gap-2">
					<Input value={flash.data.apiKey} readonly class="bg-white font-mono text-sm" />
					<Button variant="outline" size="sm" onclick={() => copyApiKey(flash.data.apiKey)}>
						{#if copied}
							<CheckCircle class="h-4 w-4" />
							Copied!
						{:else}
							<Copy class="h-4 w-4" />
							Copy
						{/if}
					</Button>
				</div>
			</CardContent>
		</Card>
	{/if}

	<div class="grid space-y-6 md:grid-cols-2">
		<div class="space-y-0.5">
			<Label class="text-base font-medium">Enable money movement</Label>
			<p class="text-sm text-muted-foreground">
				Allow this app to issue grants and send transfers, ACH payments, checks, and wires.
			</p>
		</div>
		<Switch bind:checked={$form.allowMoneyMovement} />

		<div class="space-y-0.5">
			<Label class="text-base font-medium">Enable accessing cards</Label>
			<p class="text-sm text-muted-foreground">Allow this app to access and manage user cards.</p>
		</div>
		<Switch bind:checked={$form.allowCardAccess} />

		<div class="space-y-0.5">
			<Label class="text-base font-medium">Enable fundraising</Label>
			<p class="text-sm text-muted-foreground">
				Allow this app to create invoices, donations, sponsors, and check deposits (inbound funds).
			</p>
		</div>
		<Switch bind:checked={$form.allowFundraising} />

		<div class="space-y-0.5">
			<Label class="text-base font-medium">Enable bookkeeping</Label>
			<p class="text-sm text-muted-foreground">
				Allow this app to add comments, receipts, and update transaction metadata.
			</p>
		</div>
		<Switch bind:checked={$form.allowBookkeeping} />

		<div class="space-y-0.5">
			<Label class="text-base font-medium">Enable organization admin</Label>
			<p class="text-sm text-muted-foreground">
				Allow this app to create sub-organizations, manage invitations, and request member removals.
			</p>
		</div>
		<Switch bind:checked={$form.allowOrgAdmin} />

		<div class="space-y-0.5">
			<Label class="text-base font-medium">Enable viewing financials</Label>
			<p class="text-sm text-muted-foreground">
				Allow this app to view transactions and organization balances.
			</p>
		</div>
		<Switch bind:checked={$form.allowViewFinancials} />

		<Button
			variant="secondary"
			class="w-fit md:col-span-2"
			type="submit"
			disabled={!$tainted || $submitting}
		>
			{$submitting ? 'Saving...' : 'Save permissions'}
		</Button>
	</div>
</form>
