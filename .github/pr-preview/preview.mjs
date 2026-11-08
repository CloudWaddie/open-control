// Seeds a running Open Control with sample data, sends DNS queries so the
// dashboards have something to show, and screenshots the main pages.
//
// Env: OC_API (http://127.0.0.1:8080), OC_DNS (127.0.0.1:5353), OC_TOKEN (admin),
//      OUT (output directory).
import dgram from 'node:dgram';
import { mkdirSync, writeFileSync } from 'node:fs';
import { chromium } from 'playwright';

const API = process.env.OC_API || 'http://127.0.0.1:8080';
const [dnsHost, dnsPort] = (process.env.OC_DNS || '127.0.0.1:5353').split(':');
const TOKEN = process.env.OC_TOKEN;
const OUT = process.env.OUT || 'preview';
mkdirSync(OUT, { recursive: true });

async function call(method, path, body) {
  const res = await fetch(`${API}/api/v1${path}`, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

function dnsQuery(name) {
  return new Promise((resolve) => {
    const id = Math.floor(Math.random() * 65535);
    const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
    const msg = Buffer.concat([
      Buffer.from([id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
      ...labels,
      Buffer.from([0, 0, 1, 0, 1]),
    ]);
    const sock = dgram.createSocket('udp4');
    const done = () => {
      sock.close();
      resolve();
    };
    const timer = setTimeout(done, 3000);
    sock.on('message', () => {
      clearTimeout(timer);
      done();
    });
    sock.send(msg, Number(dnsPort), dnsHost);
  });
}

async function seed() {
  const kids = await call('POST', '/profiles', { name: 'kids' });
  const exit = await call('POST', '/exits', {
    name: 'frankfurt', kind: 'wireguard', address: '203.0.113.5:51820', answer_ip: '10.77.0.1',
  });
  await call('POST', '/endpoints', { name: 'kids-laptop', profile_id: kids.id, cidrs: ['127.0.0.1'] });
  const rules = [
    { kind: 'block', matcher: 'wildcard', pattern: 'doubleclick.net' },
    { kind: 'block', matcher: 'tld', pattern: 'zip' },
    { kind: 'allow', matcher: 'domain', pattern: 'khanacademy.org' },
    { kind: 'rewrite', matcher: 'domain', pattern: 'nas.home', answer: '192.168.1.20' },
  ];
  for (const r of rules) await call('POST', `/profiles/${kids.id}/rules`, r);
  const filters = [
    { kind: 'filter', ref: 'spamtlds', state: 'block' },
    { kind: 'service', ref: 'tiktok', state: 'block' },
    { kind: 'service', ref: 'youtube', state: 'allow' },
    { kind: 'service', ref: 'netflix', state: 'redirect', exit_id: exit.id },
  ];
  for (const f of filters) {
    try {
      await call('PUT', `/profiles/${kids.id}/filters`, f);
    } catch (e) {
      console.warn(`seed: ${e.message}`); // the services registry needs network; carry on without it
    }
  }
  await new Promise((r) => setTimeout(r, 3000)); // let the snapshot reload
  const names = [
    'example.com', 'ads.doubleclick.net', 'github.com', 'evil.zip', 'nas.home', 'www.tiktok.com',
    'www.youtube.com', 'www.netflix.com', 'khanacademy.org', 'stats.doubleclick.net', 'cloudflare.com',
  ];
  for (let i = 0; i < 2; i++) for (const n of names) await dnsQuery(n);
  await new Promise((r) => setTimeout(r, 2000)); // query log flushes once a second
  return kids.id;
}

const kidsId = await seed();
const pages = [
  { id: 'overview', path: 'overview' },
  { id: 'logs', path: 'logs' },
  { id: 'profiles', path: 'profiles' },
  { id: 'filters', path: `profiles/${kidsId}/filters` },
  { id: 'services', path: `profiles/${kidsId}/services` },
  { id: 'rules', path: `profiles/${kidsId}/rules` },
  { id: 'options', path: `profiles/${kidsId}/options` },
  { id: 'domaintest', path: 'domaintest' },
  { id: 'setup', path: 'setup' },
  { id: 'endpoints', path: 'endpoints' },
  { id: 'exits', path: 'exits' },
  { id: 'accounts', path: 'accounts' },
  { id: 'tokens', path: 'tokens' },
  { id: 'audit', path: 'audit' },
];
const variants = [
  { id: 'desktop', viewport: { width: 1400, height: 900 }, scheme: 'light' },
  { id: 'dark', viewport: { width: 1400, height: 900 }, scheme: 'dark' },
  { id: 'mobile', viewport: { width: 390, height: 844 }, scheme: 'light' },
];

// PW_CHANNEL lets a local run use an installed browser (e.g. msedge).
const browser = await chromium.launch(process.env.PW_CHANNEL ? { channel: process.env.PW_CHANNEL } : {});
const errors = [];
const shots = [];
for (const v of variants) {
  const ctx = await browser.newContext({ viewport: v.viewport, colorScheme: v.scheme, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  page.on('console', (m) => m.type() === 'error' && errors.push(`${v.id}: ${m.text()}`));
  page.on('pageerror', (e) => errors.push(`${v.id}: ${e.message}`));
  await page.goto(API);
  if (v.id === 'desktop') {
    await page.waitForTimeout(500);
    await page.screenshot({ path: `${OUT}/login-desktop.png` });
    shots.push({ page: 'login', variant: 'desktop', file: 'login-desktop.png' });
  }
  await page.evaluate((t) => sessionStorage.setItem('oc_token', t), TOKEN);
  for (const p of pages) {
    await page.goto(`${API}/#/${p.path}`);
    await page.reload();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(800);
    const file = `${p.id}-${v.id}.png`;
    await page.screenshot({ path: `${OUT}/${file}`, fullPage: v.id !== 'mobile' });
    shots.push({ page: p.id, variant: v.id, file });
  }
  await ctx.close();
}
await browser.close();

writeFileSync(`${OUT}/shots.json`, JSON.stringify({ shots, errors }, null, 2));
console.log(`${shots.length} screenshots, ${errors.length} console errors`);
