// The image of the QR code of an Android enrollment token (lot AN-C2, section 12.1: rendered for the console, never
// stored nor logged). Its text is the provisioning JSON Google returned at the creation (enrollmentTokens.qrCode); a
// token shown again (reveal) has no qrCode kept (the value only is sealed): the JSON is then built from the value with
// the fields Google documents for Android Device Policy [AR: compared with Google's qrCode at AN-J]. The image is a
// data URL in the body of the answer only (Cache-Control no-store at the routes).
import QRCode from 'qrcode';
import { ANDROID_DPC_PACKAGE, ANDROID_ENROLLMENT_TOKEN_EXTRA } from '@obligarth/shared';
import type { CreatedToken } from './tokens';

const EXTRA = 'android.app.extra';

/** The provisioning JSON of a QR enrollment with Android Device Policy and this token. */
export function androidQrProvisioningJson(tokenValue: string): string {
  return JSON.stringify({
    [`${EXTRA}.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME`]: `${ANDROID_DPC_PACKAGE}/.receivers.CloudDeviceAdminReceiver`,
    [`${EXTRA}.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM`]: 'I5YvS0O5hXY46mb01BlRjq4oJJGs2kuUcHvVkAPEXlg',
    [`${EXTRA}.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION`]: 'https://play.google.com/managed/downloadManagingApp?identifier=setup',
    [`${EXTRA}.PROVISIONING_ADMIN_EXTRAS_BUNDLE`]: { [ANDROID_ENROLLMENT_TOKEN_EXTRA]: tokenValue },
  });
}

/** The token with the image of its QR code (form 'qr' only; the other forms unchanged). */
export async function withQrImage(t: CreatedToken): Promise<CreatedToken & { payload: CreatedToken['payload'] & { qrDataUrl?: string } }> {
  if (t.payload.form !== 'qr') return t;
  const text = t.payload.qrCode || androidQrProvisioningJson(t.payload.value);
  const qrDataUrl = await QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 1, width: 360 });
  return { ...t, payload: { ...t.payload, qrCode: text, qrDataUrl } };
}
