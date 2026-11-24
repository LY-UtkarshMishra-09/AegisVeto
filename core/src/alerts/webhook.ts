import { getDb } from '../db/schema.js';

export function getWebhookUrl(): string | null {
  try {
    const db = getDb();
    const row = db
      .prepare("SELECT value_json FROM service_settings WHERE key = 'webhook_url'")
      .get() as { value_json: string } | undefined;
    if (row?.value_json) {
      const parsed = JSON.parse(row.value_json);
      if (typeof parsed === 'string' && parsed.trim().startsWith('http')) {
        return parsed.trim();
      }
    }
  } catch {}
  return process.env.AEGIS_WEBHOOK_URL || null;
}

export interface AlertDetails {
  id?: string;
  quarantineId?: string;
  agentId?: string;
  sessionId?: string;
  upstreamId?: string | null;
  toolName?: string;
  reason?: string;
  diffSummary?: string;
  aiRiskScore?: number;
  aiHijacked?: boolean;
  canary?: string;
  [key: string]: unknown;
}

export function formatWebhookPayload(eventType: string, details: AlertDetails) {
  const title = `🛡️ AegisVeto Alert: ${eventType}`;
  let color = '#EF4444'; // Red default
  if (eventType === 'QUARANTINE') color = '#F59E0B'; // Amber
  if (eventType === 'TEST') color = '#4D8BFF'; // Cobalt
  if (eventType === 'SCHEMA_DRIFT') color = '#DC2626';

  const fields = [
    { title: 'Event Type', value: eventType, short: true },
    { title: 'Tool', value: details.toolName || 'N/A', short: true },
    { title: 'Agent', value: details.agentId || 'N/A', short: true },
    { title: 'Timestamp', value: new Date().toISOString(), short: true },
  ];

  if (details.reason) {
    fields.push({ title: 'Reason', value: String(details.reason), short: false });
  }
  if (details.diffSummary) {
    fields.push({ title: 'Schema Drift Diff', value: String(details.diffSummary), short: false });
  }
  if (details.aiRiskScore !== undefined) {
    fields.push({ title: 'AI Risk Score', value: `${details.aiRiskScore} / 100`, short: true });
  }

  const text = `[AegisVeto ${eventType}] ${details.toolName ? `Tool '${details.toolName}'` : ''} - ${details.reason || 'Security event detected'}`;

  return {
    content: text, // Discord format
    text, // Slack format
    attachments: [
      {
        color,
        title,
        fields,
        footer: 'AegisVeto Zero-Trust Security Gateway',
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };
}

export async function dispatchAlert(eventType: string, details: AlertDetails, overrideUrl?: string): Promise<boolean> {
  const url = overrideUrl || getWebhookUrl();
  if (!url) return false;

  const payload = formatWebhookPayload(eventType, details);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch (err) {
    console.warn(`[AegisVeto Webhook] Failed to deliver ${eventType} alert:`, err instanceof Error ? err.message : err);
    return false;
  }
}
