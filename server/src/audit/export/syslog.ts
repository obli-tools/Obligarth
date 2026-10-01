// Syslog over TLS (docs: audit-durci §8.3; RFC 5424 format, RFC 5425
// transport): <PRI>1 TIMESTAMP HOSTNAME obligarth - MSGID - <BOM>JSON, with
// PRI = 13 × 8 + severity (facility 13, log audit), framed by octet counting
// (no line injection possible). TLS 1.2 or more, the server's certificate
// and name checked (configured authority, or the system's), client
// certificate optional. No application acknowledgement: the cursor moves once
// the write is flushed to the socket; a reconnection sends again from the
// cursor (duplicates deduplicated by body.id).
import tls from 'node:tls';
import { assertSiemTarget } from '../../utils/ssrfGuard';
import { severityOf } from './message';

const BOM = Buffer.from([0xef, 0xbb, 0xbf]);

export interface SyslogTlsSettings {
  host: string;
  port: number;
  serverName?: string;
  caPem?: string;
  clientCertPem?: string;
  hostname?: string;
  maxMessageBytes: number;
  includeEvent: boolean;
}

/** One framed syslog message: "<length> <SYSLOG-MSG>". */
export function syslogFrame(message: string, o: { hostname: string; msgid: 'audit' | 'seal' | 'gap' | 'test'; timestamp: string; severity?: number }): Buffer {
  const sev = o.severity ?? severityOf(message);
  const pri = 13 * 8 + sev;
  const host = (o.hostname || '-').replace(/[^\x21-\x7e]/g, '').slice(0, 255) || '-';
  const head = Buffer.from(`<${pri}>1 ${o.timestamp} ${host} obligarth - ${o.msgid} - `, 'ascii');
  const msg = Buffer.concat([head, BOM, Buffer.from(message, 'utf8')]);
  return Buffer.concat([Buffer.from(`${msg.length} `, 'ascii'), msg]);
}

export interface SyslogConnection {
  send(frames: Buffer[]): Promise<void>;
  close(): void;
  readonly closed: boolean;
}

/** Opens a TLS connection to a checked address of `s.host`. */
export async function openSyslog(s: SyslogTlsSettings, secrets: { clientKeyPem?: string }, o: { allowLoopback: boolean; timeoutMs?: number }): Promise<SyslogConnection> {
  const [addr] = await assertSiemTarget(s.host, { allowLoopback: o.allowLoopback });
  const socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
    const sock = tls.connect({
      host: addr.address,
      port: s.port,
      servername: s.serverName || (/^[0-9.:]+$/.test(s.host) ? undefined : s.host),
      ca: s.caPem || undefined,
      cert: s.clientCertPem || undefined,
      key: secrets.clientKeyPem || undefined,
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true,
      checkServerIdentity: (_h, cert) => tls.checkServerIdentity(s.serverName || s.host, cert),
    });
    const timer = setTimeout(() => { sock.destroy(new Error('syslog TLS connection timed out')); }, o.timeoutMs ?? 10_000);
    sock.once('secureConnect', () => { clearTimeout(timer); resolve(sock); });
    sock.once('error', (err) => { clearTimeout(timer); reject(err); });
  });
  let closed = false;
  let lastError: Error | null = null;
  socket.on('error', (err) => { lastError = err; closed = true; });
  socket.on('close', () => { closed = true; });
  socket.on('data', () => { /* a collector does not answer; ignored */ });
  return {
    get closed() { return closed; },
    async send(frames: Buffer[]): Promise<void> {
      if (closed) throw lastError ?? new Error('syslog connection closed');
      const data = Buffer.concat(frames);
      await new Promise<void>((resolve, reject) => {
        socket.write(data, (err) => (err ? reject(err) : resolve()));
      });
      if (closed) throw lastError ?? new Error('syslog connection closed');
    },
    close(): void {
      closed = true;
      socket.end();
      socket.destroy();
    },
  };
}
