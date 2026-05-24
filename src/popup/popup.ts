import { generateEd25519, generateRSA, generateECDSA, type GeneratedKeyPair, type Algorithm } from '../lib/keygen.js';

const form = document.getElementById('keygen-form') as HTMLFormElement;
const algorithmSelect = document.getElementById('algorithm') as HTMLSelectElement;
const commentInput = document.getElementById('comment') as HTMLInputElement;
const passphraseInput = document.getElementById('passphrase') as HTMLInputElement;
const generateBtn = document.getElementById('generate-btn') as HTMLButtonElement;
const statusDiv = document.getElementById('status') as HTMLDivElement;
const resultDiv = document.getElementById('result') as HTMLDivElement;
const downloadPrivateBtn = document.getElementById('download-private') as HTMLButtonElement;
const downloadPublicBtn = document.getElementById('download-public') as HTMLButtonElement;
const pubkeyDisplay = document.getElementById('pubkey-display') as HTMLTextAreaElement;

let lastResult: GeneratedKeyPair | null = null;

function showStatus(msg: string, type: 'info' | 'error') {
  statusDiv.textContent = msg;
  statusDiv.className = `status ${type}`;
  statusDiv.classList.remove('hidden');
}

function hideStatus() {
  statusDiv.classList.add('hidden');
}

function downloadFile(content: string, filename: string) {
  const blob = new Blob([content], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function getFilename(algorithm: Algorithm): { priv: string; pub: string } {
  switch (algorithm) {
    case 'ed25519': return { priv: 'id_ed25519', pub: 'id_ed25519.pub' };
    case 'rsa': return { priv: 'id_rsa', pub: 'id_rsa.pub' };
    case 'ecdsa-p256': return { priv: 'id_ecdsa_p256', pub: 'id_ecdsa_p256.pub' };
    case 'ecdsa-p384': return { priv: 'id_ecdsa_p384', pub: 'id_ecdsa_p384.pub' };
    case 'ecdsa-p521': return { priv: 'id_ecdsa_p521', pub: 'id_ecdsa_p521.pub' };
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideStatus();
  resultDiv.classList.add('hidden');

  const algorithm = algorithmSelect.value as Algorithm;
  const comment = commentInput.value.trim();
  const passphrase = passphraseInput.value || undefined;

  generateBtn.disabled = true;
  generateBtn.textContent = 'Generating...';
  showStatus('Generating keypair...', 'info');

  try {
    const opts = { comment, passphrase };
    if (algorithm === 'ed25519') {
      lastResult = await generateEd25519(opts);
    } else if (algorithm === 'rsa') {
      lastResult = await generateRSA(opts);
    } else {
      lastResult = await generateECDSA(algorithm, opts);
    }

    hideStatus();
    pubkeyDisplay.value = lastResult.publicKeyLine;
    resultDiv.classList.remove('hidden');
  } catch (err) {
    showStatus(`Error: ${(err as Error).message}`, 'error');
  } finally {
    generateBtn.disabled = false;
    generateBtn.textContent = 'Generate Key Pair';
  }
});

downloadPrivateBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const { priv } = getFilename(lastResult.algorithm);
  downloadFile(lastResult.privateKeyPEM, priv);
});

downloadPublicBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const { pub } = getFilename(lastResult.algorithm);
  downloadFile(lastResult.publicKeyLine + '\n', pub);
});
