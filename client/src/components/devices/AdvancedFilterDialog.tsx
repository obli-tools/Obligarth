import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ListFilter } from 'lucide-react';
import {
  ruleParamFits, type DeviceFacets, type DeviceGroupTreeNode, type RuleNode,
} from '@obligarth/shared';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { RuleBuilder } from '@/components/rules/RuleBuilder';

// =============================================================================
// The advanced filter of the inventory (P0-5 §6): the rule builder over every field of the catalog (a view, D2), with
// the live count of the devices the list would show with it (the other filters of the list kept). Applied as the
// ?rule= of GET /api/mdm/devices and of its export: within ruleParamFits (its JSON, and that JSON once encoded).
// Full screen on a phone.
// =============================================================================

interface AdvancedFilterDialogProps {
  open: boolean;
  onClose: () => void;
  rule: RuleNode | null;
  onApply: (rule: RuleNode | null) => void;
  facets?: DeviceFacets | null;
  groups?: DeviceGroupTreeNode[];
  /** The number of devices of the list with a rule (the other filters of the list kept). */
  count: (rule: RuleNode | null) => Promise<number>;
}

export function AdvancedFilterDialog({ open, onClose, rule, onApply, facets, groups, count }: AdvancedFilterDialogProps) {
  const { t } = useTranslation();
  // A new builder at each opening: it starts from the rule applied.
  const [session, setSession] = useState(0);
  const [draft, setDraft] = useState<{ rule: RuleNode | null; valid: boolean; conditions: number }>({ rule, valid: true, conditions: 0 });
  useEffect(() => { if (open) setSession((s) => s + 1); }, [open]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="2xl"
      icon={<ListFilter className="h-4 w-4 text-accent" />}
      title={t('rules.advancedFilter.title') || 'Advanced filter'}
      bodyClassName="px-4 py-4 space-y-3"
      footer={(
        <>
          {rule && (
            <Button variant="secondary" className="mr-auto" onClick={() => { onApply(null); onClose(); }}>
              {t('rules.advancedFilter.remove') || 'Remove the filter'}
            </Button>
          )}
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={!draft.valid} onClick={() => { onApply(draft.rule); onClose(); }}>
            {t('rules.advancedFilter.apply') || 'Apply'}
          </Button>
        </>
      )}
    >
      <p className="text-xs text-text-muted">
        {t('rules.advancedFilter.hint') || 'Combine conditions on the inventory. A device whose value is unknown, or not collected by its privacy rules, does not match.'}
      </p>
      {open && (
        <RuleBuilder
          key={session}
          initialRule={rule}
          allowed="view"
          facets={facets}
          groups={groups}
          jsonFits={ruleParamFits}
          onChange={(c) => setDraft({ rule: c.rule, valid: c.valid, conditions: c.conditions })}
          preview={count}
          previewLabel={(n) => t('rules.advancedFilter.previewCount', { count: n }) || `${n} devices in the list with this filter`}
        />
      )}
    </Modal>
  );
}
