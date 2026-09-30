// =============================================================================
// Obligarth MDM — Socket.io Event Definitions
// =============================================================================

// Server → Client events
export const SocketEvents = {
  // Device events
  DEVICE_UPDATED:         'DEVICE_UPDATED',         // device status or metadata changed
  DEVICE_APPROVED:        'DEVICE_APPROVED',         // device was approved
  DEVICE_DELETED:         'DEVICE_DELETED',          // device was removed
  DEVICE_ONLINE:          'DEVICE_ONLINE',            // device came online
  DEVICE_OFFLINE:         'DEVICE_OFFLINE',           // device went offline

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

  // Client → Server
  DEVICE_SUBSCRIBE:       'DEVICE_SUBSCRIBE',
  DEVICE_UNSUBSCRIBE:     'DEVICE_UNSUBSCRIBE',
} as const;

export type SocketEvent = typeof SocketEvents[keyof typeof SocketEvents];
