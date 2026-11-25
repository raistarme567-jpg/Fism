import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createFismBackend } from './createFismBackend.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startStandaloneBackend() {
  const monoRoot = path.resolve(__dirname, '..');
  const isMonorepo = fs.existsSync(path.join(monoRoot, 'frontend'));
  const projectRootDir = isMonorepo ? monoRoot : __dirname;

  const { app, server, attachUpgradeHandler } = await createFismBackend({
    projectRootDir,
  });

  attachUpgradeHandler(server);

  if (process.env.SERVE_ADMIN === 'true') {
    const adminDir = path.resolve(monoRoot, 'admin');
    if (fs.existsSync(path.join(adminDir, 'index.html'))) {
      app.get('/admin', (req, res, next) => {
        const cleanUrl = (req.originalUrl || '').split('?')[0];
        if (!cleanUrl.endsWith('/')) {
          res.redirect(301, '/admin/');
          return;
        }
        next();
      });
      app.use('/admin', express.static(adminDir));
      app.get('/admin/', (_req, res) => {
        res.sendFile(path.join(adminDir, 'index.html'));
      });
    }
  }

  const port = Number(process.env.PORT) || 8080;
  server.listen(port, '0.0.0.0', () => {
    console.log(`FISM Standalone Backend listening on http://0.0.0.0:${port}`);
  });
}

startStandaloneBackend().catch((err) => {
  console.error('Failed to start FISM Standalone Backend:', err);
  process.exit(1);
});
