import { generateEd25519, generateRSA, type GeneratedKeyPair } from '../lib/keygen.js';

const form = document.getElementById('keygen-form') as HTMLFormElement;
const algorithmSelect = document.getElementById('algorithm') as HTMLSelectElement;
const commentInput = document.getElementById('comment') as HTMLInputElement;
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

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideStatus();
  resultDiv.classList.add('hidden');

  const algorithm = algorithmSelect.value as 'ed25519' | 'rsa';
  const comment = commentInput.value.trim();

  generateBtn.disabled = true;
  generateBtn.textContent = 'Generating...';
  showStatus('Generating keypair...', 'info');

  try {
    if (algorithm === 'ed25519') {
      lastResult = await generateEd25519(comment);
    } else {
      lastResult = await generateRSA(comment);
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
  const filename = lastResult.algorithm === 'ed25519' ? 'id_ed25519' : 'id_rsa';
  downloadFile(lastResult.privateKeyPEM, filename);
});

downloadPublicBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const filename = lastResult.algorithm === 'ed25519' ? 'id_ed25519.pub' : 'id_rsa.pub';
  downloadFile(lastResult.publicKeyLine + '\n', filename);
});
