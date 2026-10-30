import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { config } from '../config';
import { ipGate, mcpAuth } from './auth';
import { handleRpc } from './transport';

// =============================================================================
// /mcp (docs: specs mcp-server §3.1): mounted by app.ts right after the bridge
// agent's surface, before cors, the parsers, the cookies, the session, the
// database context of the console, the step-up capture and the API limiter: no
// session can be read nor written here, no cookie is set. In order:
//   0. Cache-Control: no-store on every answer;
//   1. the IP gate (blocks, strict mode; memory only);
//   2. the Origin guard (DNS rebinding): an Origin other than the console's is
//      refused; command-line clients send none; no CORS header is emitted;
//   3. POST only (GET and DELETE: 405 Allow: POST; stateless, no SSE stream);
//   4. its own JSON parser (256 kB, application/json; 415 otherwise; malformed
//      JSON: 400 with -32700);
//   5. the authentication of the key; 6. the JSON-RPC handler.
// =============================================================================

const parse = express.json({ limit: '256kb', type: ['application/json'] });

function noStore(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('Cache-Control', 'no-store');
  next();
}

function originGuard(req: Request, res: Response, next: NextFunction): void {
  const origin = req.get('Origin');
  if (origin !== undefined && origin !== config.clientOrigin) {
    res.status(403).json({ jsonrpc: '2.0', id: null, error: { code: -32003, message: 'Forbidden origin' } });
    return;
  }
  next();
}

function postOnly(req: Request, res: Response, next: NextFunction): void {
  if (req.method === 'POST' && (req.path === '/' || req.path === '')) { next(); return; }
  res.setHeader('Allow', 'POST');
  res.status(405).json({ jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Method not allowed' } });
}

function jsonBody(req: Request, res: Response, next: NextFunction): void {
  if (!req.is('application/json')) {
    res.status(415).json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Content-Type must be application/json' } });
    return;
  }
  parse(req, res, (err?: unknown) => {
    if (err) {
      const e = err as { type?: string; status?: number };
      if (e.type === 'entity.too.large' || e.status === 413) {
        res.status(413).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Request too large' } });
        return;
      }
      res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    next();
  });
}

export function createMcpRouter(): Router {
  const router = Router();
  router.use(noStore);
  router.use(ipGate);
  router.use(originGuard);
  router.use(postOnly);
  router.use(jsonBody);
  router.use(mcpAuth);
  router.post('/', (req, res) => {
    handleRpc(req, res).catch(() => {
      if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Internal error' } });
    });
  });
  return router;
}
