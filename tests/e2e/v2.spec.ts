import { test, expect, chromium, type BrowserContext, type Page } from '@playwright/test';
import { execSync } from 'child_process';
import { writeFileSync, unlinkSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const sshpk = require('sshpk');

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const EXTENSION_PATH = resolve(__dirname, '../../dist');

async function getExtensionId(context: BrowserContext): Promise<string> {
  let sw = context.serviceWorkers().find(w => w.url().startsWith('chrome-extension://'));
  if (!sw) {
    sw = await context.waitForEvent('serviceworker', { timeout: 10000 });
  }
  return sw.url().split('/')[2];
}

test.describe('SSH Key Generation v2 E2E', () => {
  let context: BrowserContext;
  let downloadDir: string;

  test.beforeAll(async () => {
    execSync('npx vite build', { cwd: resolve(__dirname, '../..'), stdio: 'pipe' });
    downloadDir = mkdtempSync(join(tmpdir(), 'ssh-e2e-v2-'));
  });

  test.beforeEach(async () => {
    context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
        '--no-sandbox',
        '--disable-gpu',
      ],
      acceptDownloads: true,
    });
  });

  test.afterEach(async () => {
    if (context) await context.close();
  });

  async function openPopup(): Promise<Page> {
    const extensionId = await getExtensionId(context);
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
    await page.waitForLoadState('domcontentloaded');
    return page;
  }

  async function generateAndExtractKeys(page: Page, algorithm: string, comment: string, passphrase?: string) {
    await page.selectOption('#algorithm', algorithm);
    await page.fill('#comment', comment);
    if (passphrase) {
      await page.fill('#passphrase', passphrase);
    }
    await page.click('#generate-btn');
    await page.waitForSelector('#result:not(.hidden)', { timeout: 30000 });

    const publicKey = await page.evaluate(() => {
      return (document.getElementById('pubkey-display') as HTMLTextAreaElement).value;
    });

    const privateKey = await page.evaluate(() => {
      return new Promise<string>((resolve) => {
        const origCreateObjectURL = URL.createObjectURL.bind(URL);
        URL.createObjectURL = (blob: Blob) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.readAsText(blob);
          return origCreateObjectURL(blob);
        };
        document.getElementById('download-private')!.click();
      });
    });

    return { privateKey, publicKey };
  }

  test('generates Ed25519 with passphrase', async () => {
    const page = await openPopup();
    const { privateKey, publicKey } = await generateAndExtractKeys(
      page, 'ed25519', 'e2e-pass@ed25519', 'testpass123'
    );

    expect(publicKey).toContain('ssh-ed25519');
    expect(privateKey).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

    // Validate with ssh-keygen using passphrase
    const privPath = join(downloadDir, 'e2e_ed25519_enc');
    writeFileSync(privPath, privateKey, { mode: 0o600 });
    const out = execSync(`/usr/bin/ssh-keygen -y -P testpass123 -f ${privPath}`).toString().trim();
    expect(out).toContain('ssh-ed25519');
    // Public key blob should match
    const pubBlob = publicKey.split(' ')[1];
    expect(out).toContain(pubBlob);
    unlinkSync(privPath);
  });

  test('generates ECDSA P-256', async () => {
    const page = await openPopup();
    const { privateKey, publicKey } = await generateAndExtractKeys(
      page, 'ecdsa-p256', 'e2e@p256'
    );

    expect(publicKey).toContain('ecdsa-sha2-nistp256');
    expect(privateKey).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

    // Validate with sshpk
    const parsedPub = sshpk.parseKey(publicKey, 'ssh');
    expect(parsedPub.type).toBe('ecdsa');

    // Validate with ssh-keygen
    const privPath = join(downloadDir, 'e2e_p256');
    writeFileSync(privPath, privateKey, { mode: 0o600 });
    const out = execSync(`/usr/bin/ssh-keygen -y -f ${privPath}`).toString().trim();
    expect(out).toContain('ecdsa-sha2-nistp256');
    unlinkSync(privPath);
  });

  test('generates ECDSA P-384', async () => {
    const page = await openPopup();
    const { privateKey, publicKey } = await generateAndExtractKeys(
      page, 'ecdsa-p384', 'e2e@p384'
    );

    expect(publicKey).toContain('ecdsa-sha2-nistp384');

    const privPath = join(downloadDir, 'e2e_p384');
    writeFileSync(privPath, privateKey, { mode: 0o600 });
    const out = execSync(`/usr/bin/ssh-keygen -y -f ${privPath}`).toString().trim();
    expect(out).toContain('ecdsa-sha2-nistp384');
    unlinkSync(privPath);
  });

  test('generates ECDSA P-521', async () => {
    const page = await openPopup();
    const { privateKey, publicKey } = await generateAndExtractKeys(
      page, 'ecdsa-p521', 'e2e@p521'
    );

    expect(publicKey).toContain('ecdsa-sha2-nistp521');

    const privPath = join(downloadDir, 'e2e_p521');
    writeFileSync(privPath, privateKey, { mode: 0o600 });
    const out = execSync(`/usr/bin/ssh-keygen -y -f ${privPath}`).toString().trim();
    expect(out).toContain('ecdsa-sha2-nistp521');
    unlinkSync(privPath);
  });
});
