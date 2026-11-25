import type express from 'express';
import type http from 'node:http';

export function createFismBackend(options?: {
  projectRootDir?: string;
}): Promise<{
  app: express.Express;
  server: http.Server;
  attachUpgradeHandler: (targetServer?: http.Server) => void;
}>;
