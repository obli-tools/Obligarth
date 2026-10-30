import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronRight, KeyRound } from 'lucide-react';
import { useAuthStore } from '@/store/authStore';

// The link of the profile to the user's access keys of the MCP server (docs: specs mcp-server §6.5), shown to the
// holders of mcp.access_keys (a platform administrator always), for local and SSO accounts alike.

export function AccessKeysLink() {
  const { t } = useTranslation();
  const { isAdmin, permissions } = useAuthStore();
  if (!isAdmin() && !(permissions?.tenantCapabilities ?? []).includes('mcp.access_keys')) return null;
  return (
    <Link to="/access-keys" className="mt-4 flex items-center gap-3 rounded-lg bg-bg-secondary p-4 transition-colors hover:bg-bg-tertiary">
      <KeyRound size={18} className="shrink-0 text-accent" />
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium text-text-primary">{t('accessKeys.title') || 'Access keys for AI agents'}</span>
        <span className="block text-xs text-text-muted">
          {t('accessKeys.profileHint') || 'Let an AI agent such as Claude Code act as you, within your rights, through the MCP server.'}
        </span>
      </span>
      <ChevronRight size={16} className="shrink-0 text-text-muted" />
    </Link>
  );
}
