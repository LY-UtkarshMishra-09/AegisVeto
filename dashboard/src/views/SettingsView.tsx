import React, { useState, useEffect } from 'react';
import { ServiceSettings } from '../types';
import { Brain, Clock, ShieldAlert, Plus, Trash2, CheckCircle2, Save, Send } from 'lucide-react';

interface SettingsViewProps {
  initialSettings: ServiceSettings;
  onSaveSettings: (settings: Partial<ServiceSettings>) => Promise<boolean>;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  initialSettings,
  onSaveSettings,
}) => {
  // Provider settings
  const [provider, setProvider] = useState<'ollama' | 'groq'>(
    initialSettings.layer2_provider?.provider || 'ollama'
  );
  const [ollamaUrl, setOllamaUrl] = useState(
    initialSettings.layer2_provider?.ollamaUrl || 'http://localhost:11434'
  );
  const [ollamaModel, setOllamaModel] = useState(
    initialSettings.layer2_provider?.ollamaModel || 'qwen2.5:7b'
  );
  const [groqModel, setGroqModel] = useState(
    initialSettings.layer2_provider?.groqModel || 'llama-3.3-70b-versatile'
  );
  const [groqApiKey, setGroqApiKey] = useState(
    initialSettings.layer2_provider?.apiKey || ''
  );

  // Approval SLA & Webhook
  const [slaSeconds, setSlaSeconds] = useState(
    initialSettings.approval_sla_seconds ?? 300
  );
  const [webhookUrl, setWebhookUrl] = useState(
    initialSettings.webhook_url || ''
  );

  // Canaries & Decoys
  const [canaries, setCanaries] = useState<string[]>(
    initialSettings.canary_tokens || ['aegis_canary_9921', 'ak_live_sec_tripwire_7701']
  );
  const [newCanary, setNewCanary] = useState('');
  const [decoyToolName, setDecoyToolName] = useState(
    initialSettings.decoy_tool_name || 'export_admin_secrets'
  );

  const [isSaving, setIsSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [pingSuccess, setPingSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (initialSettings.layer2_provider) {
      setProvider(initialSettings.layer2_provider.provider);
      setOllamaUrl(initialSettings.layer2_provider.ollamaUrl);
      setOllamaModel(initialSettings.layer2_provider.ollamaModel);
      setGroqModel(initialSettings.layer2_provider.groqModel);
      setGroqApiKey(initialSettings.layer2_provider.apiKey || '');
    }
    if (initialSettings.approval_sla_seconds !== undefined) {
      setSlaSeconds(initialSettings.approval_sla_seconds);
    }
    if (initialSettings.webhook_url !== undefined) {
      setWebhookUrl(initialSettings.webhook_url);
    }
    if (initialSettings.canary_tokens) {
      setCanaries(initialSettings.canary_tokens);
    }
    if (initialSettings.decoy_tool_name) {
      setDecoyToolName(initialSettings.decoy_tool_name);
    }
  }, [initialSettings]);

  const handleAddCanary = () => {
    if (newCanary.trim() && !canaries.includes(newCanary.trim())) {
      setCanaries([...canaries, newCanary.trim()]);
      setNewCanary('');
    }
  };

  const handleRemoveCanary = (token: string) => {
    setCanaries(canaries.filter((c) => c !== token));
  };

  const handleSave = async () => {
    setIsSaving(true);
    setSavedSuccess(false);
    try {
      const payload: Partial<ServiceSettings> = {
        layer2_provider: {
          provider,
          ollamaUrl,
          ollamaModel,
          groqModel,
          apiKey: groqApiKey,
        },
        approval_sla_seconds: Number(slaSeconds) || 300,
        webhook_url: webhookUrl,
        canary_tokens: canaries,
        decoy_tool_name: decoyToolName,
      };

      const ok = await onSaveSettings(payload);
      if (ok) {
        setSavedSuccess(true);
        setTimeout(() => setSavedSuccess(false), 3000);
      }
    } finally {
      setIsSaving(false);
    }
  };

  const handleTestWebhook = async () => {
    setPingSuccess('Dispatching test ping to webhook...');
    try {
      const res = await fetch('http://localhost:3000/v1/settings/test-webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ webhookUrl }),
      });
      if (res.ok) {
        const data = await res.json();
        setPingSuccess(data.status === 'delivered' ? '✓ Webhook alert delivered' : '✓ Alert queued to webhook');
      } else {
        setPingSuccess('Failed to deliver test alert');
      }
    } catch {
      setPingSuccess('Failed to connect to gateway');
    }
    setTimeout(() => setPingSuccess(null), 3500);
  };

  return (
    <div className="flex flex-col h-full bg-[#000000] text-[#F4F6F8] overflow-y-auto">
      {/* Top Header */}
      <div className="h-11 border-b border-[#1E1E22] px-5 flex items-center justify-between bg-[#000000] sticky top-0 z-10">
        <span className="text-xs font-mono font-medium text-[#F4F6F8] uppercase tracking-wider">
          Control Plane Configuration
        </span>
        <div className="flex items-center gap-3">
          {savedSuccess && (
            <span className="text-xs font-mono text-[#4D8BFF] flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Saved
            </span>
          )}
          <button
            disabled={isSaving}
            onClick={handleSave}
            className="px-3 py-1 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] text-xs font-mono font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            {isSaving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </div>

      <div className="max-w-4xl w-full p-6 space-y-8 divide-y divide-[#1E1E22] font-mono text-xs">
        {/* Section 1: Layer 2 AI Provider */}
        <div className="space-y-4 pt-0">
          <div className="flex items-center gap-2 text-sm font-medium text-[#F4F6F8]">
            <Brain className="w-4 h-4 text-[#4D8BFF]" />
            Layer 2 AI Semantic Brain
          </div>
          <div className="text-[11px] text-[#8E95A2] leading-relaxed">
            Powers asynchronous background intent verification for quarantined items. Zero LLMs run in the &lt;10ms Layer 1 hot path.
          </div>

          <div className="space-y-3 max-w-xl">
            <div>
              <label className="text-[#8E95A2] block mb-1">Active Backend</label>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 cursor-pointer text-[#F4F6F8]">
                  <input
                    type="radio"
                    name="provider"
                    value="ollama"
                    checked={provider === 'ollama'}
                    onChange={() => setProvider('ollama')}
                    className="accent-[#2563EB]"
                  />
                  Ollama (Local / Air-Gapped)
                </label>
                <label className="flex items-center gap-2 cursor-pointer text-[#F4F6F8]">
                  <input
                    type="radio"
                    name="provider"
                    value="groq"
                    checked={provider === 'groq'}
                    onChange={() => setProvider('groq')}
                    className="accent-[#2563EB]"
                  />
                  Groq (Cloud LPUs)
                </label>
              </div>
            </div>

            {provider === 'ollama' ? (
              <>
                <div>
                  <label className="text-[#8E95A2] block mb-1">Ollama Base URL</label>
                  <input
                    type="text"
                    value={ollamaUrl}
                    onChange={(e) => setOllamaUrl(e.target.value)}
                    className="w-full bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                  />
                </div>
                <div>
                  <label className="text-[#8E95A2] block mb-1">Ollama Model</label>
                  <input
                    type="text"
                    value={ollamaModel}
                    onChange={(e) => setOllamaModel(e.target.value)}
                    className="w-full bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                  />
                </div>
              </>
            ) : (
              <>
                <div>
                  <label className="text-[#8E95A2] block mb-1">Groq Model</label>
                  <input
                    type="text"
                    value={groqModel}
                    onChange={(e) => setGroqModel(e.target.value)}
                    className="w-full bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                  />
                </div>
                <div>
                  <label className="text-[#8E95A2] block mb-1">Groq API Key</label>
                  <input
                    type="password"
                    placeholder="gsk_..."
                    value={groqApiKey}
                    onChange={(e) => setGroqApiKey(e.target.value)}
                    className="w-full bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                  />
                </div>
              </>
            )}
          </div>
        </div>

        {/* Section 2: Approval SLA & Webhooks */}
        <div className="space-y-4 pt-6">
          <div className="flex items-center gap-2 text-sm font-medium text-[#F4F6F8]">
            <Clock className="w-4 h-4 text-[#4D8BFF]" />
            Approval SLA & Webhooks
          </div>

          <div className="space-y-3 max-w-xl">
            <div>
              <label className="text-[#8E95A2] block mb-1">Human-in-the-Loop SLA Timeout (seconds)</label>
              <input
                type="number"
                min="10"
                max="86400"
                value={slaSeconds}
                onChange={(e) => setSlaSeconds(Number(e.target.value))}
                className="w-full bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
              <span className="text-[11px] text-[#8E95A2] mt-0.5 block">
                Pending quarantines not resolved within this SLA are automatically expired and vetoed.
              </span>
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Incident Webhook URL (Slack / Discord / PagerDuty)</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="https://hooks.slack.com/services/..."
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  className="flex-1 bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                />
                <button
                  type="button"
                  onClick={handleTestWebhook}
                  className="px-3 py-1.5 border border-[#1E1E22] hover:border-[#4D8BFF] text-[#F4F6F8] flex items-center gap-1.5 transition-colors whitespace-nowrap"
                >
                  <Send className="w-3 h-3 text-[#4D8BFF]" />
                  Test Ping
                </button>
              </div>
              {pingSuccess && (
                <div className="text-[11px] text-[#4D8BFF] mt-1">{pingSuccess}</div>
              )}
            </div>
          </div>
        </div>

        {/* Section 3: Canary & Decoy Registry */}
        <div className="space-y-4 pt-6">
          <div className="flex items-center gap-2 text-sm font-medium text-[#F4F6F8]">
            <ShieldAlert className="w-4 h-4 text-[#EF4444]" />
            Synthetic Canary & Decoy Trap Registry
          </div>
          <div className="text-[11px] text-[#8E95A2] leading-relaxed">
            Tripwires that instantly trigger CRITICAL_TRIPWIRE and terminate the agent session upon invocation or argument leak.
          </div>

          <div className="space-y-3 max-w-xl">
            <div>
              <label className="text-[#8E95A2] block mb-1">Decoy Honeypot Tool Name</label>
              <input
                type="text"
                value={decoyToolName}
                onChange={(e) => setDecoyToolName(e.target.value)}
                className="w-full bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Active Canary Leak Tokens</label>
              <div className="space-y-1.5 mb-2">
                {canaries.map((token) => (
                  <div
                    key={token}
                    className="flex items-center justify-between p-2 border border-[#1E1E22] bg-[#09090B]"
                  >
                    <span className="text-xs text-[#F4F6F8] font-mono">{token}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveCanary(token)}
                      className="text-[#8E95A2] hover:text-[#EF4444] transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="e.g. ak_live_sec_prod_secret"
                  value={newCanary}
                  onChange={(e) => setNewCanary(e.target.value)}
                  className="flex-1 bg-[#09090B] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                />
                <button
                  type="button"
                  onClick={handleAddCanary}
                  className="px-3 py-1.5 border border-[#1E1E22] hover:border-[#4D8BFF] text-[#F4F6F8] flex items-center gap-1.5 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add Token
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
