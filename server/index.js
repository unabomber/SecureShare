import { loadConfig } from './config.js';
import { createApp } from './app.js';

const cfg = loadConfig();
const app = createApp(cfg);

app.server.listen(cfg.port, cfg.host, () => {
  // Deliberately no request logging: it would record IPs and drop ids.
  console.log(`sealdrop listening on ${cfg.host}:${cfg.port} (pow=${cfg.powBits} bits, max secret=${cfg.maxSecretBytes}B)`);
});

const stop = () => app.close().then(() => process.exit(0));
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
