// =============================================================================
// Obligarth MDM — Socket.io Event Definitions
// =============================================================================

// Server → Client events
export const SocketEvents = {
  // Device events
  DEVICE_UPDATED:         'DEVICE_UPDATED',         // a record of the registry changed ({ deviceId, tenantId })
  DEVICE_DELETED:         'DEVICE_DELETED',          // device was removed

  // Command events
  COMMAND_UPDATED:        'COMMAND_UPDATED',          // command status changed
  COMMAND_RESULT:         'COMMAND_RESULT',           // command finished with result

  // Group events
  GROUP_CREATED:          'GROUP_CREATED',
  GROUP_UPDATED:          'GROUP_UPDATED',
  GROUP_DELETED:          'GROUP_DELETED',
  GROUP_MOVED:            'GROUP_MOVED',

  // Notification & alert events
  NOTIFICATION_SENT:      'NOTIFICATION_SENT',
  NOTIFICATION_NEW:       'NOTIFICATION_NEW',         // live alert created
  NOTIFICATION_READ:      'NOTIFICATION_READ',        // live alerts marked read server-side ({ ids, readAt })
  // Live alerts resolved server-side ({ ids: number[] }): their incident
  // recovered or escalated to a new row, or its device was deleted. Resolved
  // rows are hidden from every live-alert list; clients drop them.
  NOTIFICATION_RESOLVED:  'NOTIFICATION_RESOLVED',

  // Settings
  SETTINGS_UPDATED:       'SETTINGS_UPDATED',

  // Maintenance
  MAINTENANCE_CHANGED:    'MAINTENANCE_CHANGED',

  // Guards against mass erasure (PLT-11): a guarded action changed state
  // (PendingActionDto), the emergency freeze of a tenant changed
  // (GuardStateChanged). Both to the tenant room.
  GUARD_ACTION_UPDATED:   'GUARD_ACTION_UPDATED',
  GUARD_STATE_CHANGED:    'GUARD_STATE_CHANGED',

  // Policies (modele-donnees-mdm §11.2), identifiers only, to the tenant room:
  // policies created, changed or published ({ policyIds }), effective
  // configuration of devices recomputed by a resolution ({ deviceIds }).
  POLICY_CHANGED:         'POLICY_CHANGED',
  DEVICE_CONFIG_CHANGED:  'DEVICE_CONFIG_CHANGED',
  // Dynamic groups (P0-5 T5): the members of groups changed by an automatic computation ({ smartGroupIds }).
  SMART_GROUP_CHANGED:    'SMART_GROUP_CHANGED',

  // Apple integration (integration-apple-edge §12.4): identifiers only, the
  // client reads the objects back through the REST routes (scopes applied).
  // APPLE_DEVICE_CHANGED { deviceIds }, MDM_COMMAND_CHANGED { commandIds,
  // deviceIds } to the tenant room; ENROLLMENT_SESSION_CHANGED { sessionIds }
  // and INTEGRATION_CHANGED { kinds } to the tenant's admin room.
  APPLE_DEVICE_CHANGED:        'APPLE_DEVICE_CHANGED',
  MDM_COMMAND_CHANGED:         'MDM_COMMAND_CHANGED',
  ENROLLMENT_SESSION_CHANGED:  'ENROLLMENT_SESSION_CHANGED',
  INTEGRATION_CHANGED:         'INTEGRATION_CHANGED',

  // Remote assistance (P0-15 §4.2): a session changed state (RemoteSessionChanged
  // of mdm/remote: ids, state, reason of its end; never a token), to the room of
  // its requester and to the tenant's admin room.
  REMOTE_SESSION_CHANGED:      'REMOTE_SESSION_CHANGED',

  // Client → Server
  DEVICE_SUBSCRIBE:       'DEVICE_SUBSCRIBE',
  DEVICE_UNSUBSCRIBE:     'DEVICE_UNSUBSCRIBE',
} as const;

export type SocketEvent = typeof SocketEvents[keyof typeof SocketEvents];
