/**
 * Product name shown by the web client. Translations never write it: they say
 * {{appName}}, which i18next fills in from here (interpolation.defaultVariables,
 * i18n/index.ts). The server has its own, configurable name (APP_NAME →
 * config.appName): TOTP issuer, notifications, e-mails.
 */
export const APP_NAME = 'Obligarth';
