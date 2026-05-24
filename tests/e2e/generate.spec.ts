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

test.describe('SSH Key Generation E2E', () => {
  let context: BrowserContext;
  let downloadDir: string;

  test.beforeAll(async () => {
    execSync('npx vite build', { cwd: resolve(__dirname, '../..'), stdio: 'pipe' });
    downloadDir = mkdtempSync(join(tmpdir(), 'ssh-e2e-'));
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

  async function generateAndExtractKeys(page: Page, algorithm: string, comment: string) {
    await page.selectOption('#algorithm', algorithm);
    await page.fill('#comment', comment);
    await page.click('#generate-btn');
    await page.waitForSelector('#result:not(.hidden)', { timeout: 30000 });

    // Extract key data directly from the page's JS context
    const keys = await page.evaluate(() => {
      // Access the lastResult variable from popup.ts
      // We can't access module scope directly, so let's read from the DOM and intercept downloads
      const pubKey = (document.getElementById('pubkey-display') as HTMLTextAreaElement).value;
      return { publicKey: pubKey };
    });

    // Get the private key by intercepting the download blob
    const privateKey = await page.evaluate(() => {
      return new Promise<string>((resolve) => {
        // Override createElement to intercept the download
        const origCreateElement = document.createElement.bind(document);
        const origCreateObjectURL = URL.createObjectURL.bind(URL);

        URL.createObjectURL = (blob: Blob) => {
          // Read the blob content
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.readAsText(blob);
          return origCreateObjectURL(blob);
        };

        // Click download private button
        document.getElementById('download-private')!.click();
      });
    });

    return { privateKey, publicKey: keys.publicKey };
  }

  test('generates Ed25519 keypair', async () => {
    const page = await openPopup();
    const { privateKey, publicKey } = await generateAndExtractKeys(page, 'ed25519', 'e2e-test@ed25519');

    expect(publicKey).toContain('ssh-ed25519');
    expect(publicKey).toContain('e2e-test@ed25519');
    expect(privateKey).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

    // Validate with sshpk
    const parsedPriv = sshpk.parsePrivateKey(privateKey, 'ssh');
    const parsedPub = sshpk.parseKey(publicKey, 'ssh');
    expect(parsedPriv.type).toBe('ed25519');
    expect(parsedPub.type).toBe('ed25519');

    // Sign and verify
    const msg = Buffer.from('test message');
    const signer = parsedPriv.createSign('sha512');
    signer.update(msg);
    const sig = signer.sign();
    const verifier = parsedPub.createVerify('sha512');
    verifier.update(msg);
    expect(verifier.verify(sig)).toBe(true);

    // Validate with ssh-keygen ground truth
    const privPath = join(downloadDir, 'e2e_ed25519');
    writeFileSync(privPath, privateKey, { mode: 0o600 });
    const out = execSync(`/usr/bin/ssh-keygen -y -f ${privPath}`).toString().trim();
    expect(out).toContain('ssh-ed25519');
    unlinkSync(privPath);
  });

  test('generates RSA-3072 keypair', async () => {
    const page = await openPopup();
    const { privateKey, publicKey } = await generateAndExtractKeys(page, 'rsa', 'e2e-test@rsa');

    expect(publicKey).toContain('ssh-rsa');
    expect(publicKey).toContain('e2e-test@rsa');
    expect(privateKey).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

    const parsedPriv = sshpk.parsePrivateKey(privateKey, 'ssh');
    const parsedPub = sshpk.parseKey(publicKey, 'ssh');
    expect(parsedPriv.type).toBe('rsa');
    expect(parsedPub.type).toBe('rsa');

    // Sign and verify
    const msg = Buffer.from('test message rsa');
    const signer = parsedPriv.createSign('sha256');
    signer.update(msg);
    const sig = signer.sign();
    const verifier = parsedPub.createVerify('sha256');
    verifier.update(msg);
    expect(verifier.verify(sig)).toBe(true);

    // Validate with ssh-keygen
    const privPath = join(downloadDir, 'e2e_rsa');
    writeFileSync(privPath, privateKey, { mode: 0o600 });
    const out = execSync(`/usr/bin/ssh-keygen -y -f ${privPath}`).toString().trim();
    expect(out).toContain('ssh-rsa');
    unlinkSync(privPath);
  });
});
