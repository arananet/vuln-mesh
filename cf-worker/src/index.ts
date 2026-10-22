import { Container, getContainer } from "@cloudflare/containers";

/**
 * Cloudflare Containers wrapper for vuln-mesh.
 *
 * The application is the existing FastAPI backend (Dockerfile.backend):
 * one uvicorn process serves the dashboard UI, its static assets, the
 * /api/* REST endpoints and the /events SSE stream from a single origin,
 * so this Worker only routes traffic to the container. The old Railway
 * nginx frontend service is not needed on Cloudflare: the dashboard
 * already falls back to same-origin API calls when no BACKEND_URL
 * config.js exists.
 *
 * Runtime configuration reaches the container from this Worker's own
 * bindings (dashboard or API, never from this repo). Only bindings that
 * exist are passed through:
 *   CF_ACCOUNT_ID, CF_API_TOKEN  AI Gateway credentials for the
 *                                cloudflare adapter (token minted at
 *                                deploy time, Workers AI scope only)
 *   ADMIN_USER, ADMIN_PASS       dashboard login; ADMIN_PASS must be set
 *                                in production or the app serves the
 *                                dashboard without authentication
 *   DATABASE_URL                 optional; without it the scan history
 *                                endpoints degrade to empty results
 *   SCAN_TARGET, SCAN_CONFIG     optional auto-scan on boot
 */

interface VulnMeshEnv {
  VULN_MESH: DurableObjectNamespace<VulnMeshContainer>;
  CF_ACCOUNT_ID?: string;
  CF_API_TOKEN?: string;
  ADMIN_USER?: string;
  ADMIN_PASS?: string;
  DATABASE_URL?: string;
  SCAN_TARGET?: string;
  SCAN_CONFIG?: string;
}

export class VulnMeshContainer extends Container {
  defaultPort = 8000;
  // Scans are long-running; while the dashboard is open its polling and
  // the SSE stream keep the container busy anyway. The longer window
  // only matters for unattended scans (see the migration spec).
  sleepAfter = "30m";

  constructor(ctx: DurableObjectState, env: VulnMeshEnv) {
    super(ctx, env);
    this.envVars = {
      PORT: "8000",
      ...(env.CF_ACCOUNT_ID ? { CF_ACCOUNT_ID: env.CF_ACCOUNT_ID } : {}),
      ...(env.CF_API_TOKEN ? { CF_API_TOKEN: env.CF_API_TOKEN } : {}),
      ...(env.ADMIN_USER ? { ADMIN_USER: env.ADMIN_USER } : {}),
      ...(env.ADMIN_PASS ? { ADMIN_PASS: env.ADMIN_PASS } : {}),
      ...(env.DATABASE_URL ? { DATABASE_URL: env.DATABASE_URL } : {}),
      ...(env.SCAN_TARGET ? { SCAN_TARGET: env.SCAN_TARGET } : {}),
      ...(env.SCAN_CONFIG ? { SCAN_CONFIG: env.SCAN_CONFIG } : {}),
    };
  }
}

export default {
  async fetch(request: Request, env: VulnMeshEnv): Promise<Response> {
    // Singleton on purpose: pipeline state lives in the app process
    // memory and it rejects concurrent scans, so extra instances would
    // split the event stream instead of helping.
    const container = getContainer(env.VULN_MESH);
    return container.fetch(request);
  },
};
