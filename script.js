// Always clear stored token on page load
window.addEventListener('load', () => {
  sessionStorage.clear();
  handleUrlFragment();
});

// State management
const state = {
  token: null,
  encryptedData: null
}

// --- DOM References auth ---
const tokenInput = document.getElementById('tokenInput');
const authArea = document.getElementById('authArea');
const actionArea = document.getElementById('actionArea');

// --- DOM References upload ---
const textUpload = document.getElementById('textInput');
const fileUpload = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const btnUpload = document.getElementById('btnUploadContent');
const fileNameDisplay = document.getElementById('fileName');
const uploadArea = document.getElementById('uploadArea');

function handleUrlFragment() {
  const hash = window.location.hash;
  console.log('Fragment detected:', hash);
  
  if (!hash.startsWith('#v=1&')) return;
  
  try {
    const params = new URLSearchParams(hash.slice(1));
    const version = params.get('v');
    const salt = params.get('salt');
    const iv = params.get('iv');
    const ct = params.get('ct');
    const iter = params.get('iter');
    
    console.log('Fragment params:', { version, salt, iv, ct, iter });
    
    if (version === '1' && salt && iv && ct && iter) {
      state.encryptedData = { salt, iv, ct, iter: parseInt(iter) };
      console.log('Encrypted data set:', state.encryptedData);
      
      // Scrub URL fragment immediately
      history.replaceState(null, '', window.location.pathname + window.location.search);
      
      // Show PIN dialog to unlock
      showPinDialog();
    }
  } catch (error) {
    console.error('Fragment processing error:', error);
    setStatus('Invalid encrypted URL format', 'error');
  }
}

// --- Helpers ---
function isValidToken(token) {
  const classic = /^gh[pousr]_[A-Za-z0-9]{36}$/;
  const fineGrained = /^github_pat_[A-Za-z0-9_]{82,}$/;
  return classic.test(token) || fineGrained.test(token);
}

function storeToken(token) {
    sessionStorage.setItem('gh_token', token);
}

function swapActionArea() {
    authArea.classList.add('hidden');
    actionArea.classList.remove('hidden');
}

function updateUploadButtonState() {
    const hasText = textUpload.value.trim() !== '';
    const hasFile = fileUpload.files.length > 0;

    btnUpload.disabled = !(hasText || hasFile);
}

function createGistPayload(filesObj) {
  return {
    description: 'Uploaded via pastr',
    public: false,
    files: filesObj
  };
}

async function uploadCombinedGist({ textContent, file }, token) {
  const files = {};

  if (textContent.trim() !== '') {
    files['pastr.txt'] = { content: textContent.trim() };
  }

  if (file) {
    const fileContent = await readFileAsText(file);
    files[file.name] = { content: fileContent };
  }

  if (Object.keys(files).length === 0) {
    throw new Error("No content to upload.");
  }

  const payload = createGistPayload(files);

  const response = await fetch('https://api.github.com/gists', {
    method: 'POST',
    headers: {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`Gist upload failed: ${response.status}`);
  }

  const result = await response.json();
  return result.html_url;
}

async function handleUpload() {
  const token = sessionStorage.getItem('gh_token');
  const text = textUpload.value;
  const file = fileUpload.files[0];

  const statusEl = document.getElementById('uploadStatus');
  statusEl.textContent = 'Uploading...';
  statusEl.className = 'uploading';  // <-- applies light gray style
  statusEl.classList.remove('hidden');
  btnUpload.disabled = true;

  try {
    const url = await uploadCombinedGist({ textContent: text, file: file }, token);
    statusEl.innerHTML = `Gist created: <a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`;
    statusEl.className = 'success'; // <-- green on success

    // Reset inputs
    textUpload.value = '';
    fileUpload.value = '';
    fileNameDisplay.textContent = '';  // <-- clear file name
  } catch (err) {
    statusEl.textContent = `Upload failed: ${err.message}`;
    statusEl.className = 'error'; // <-- red on error
  } finally {
    updateUploadButtonState();
  }
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

function setupDragAndDrop(dropArea, fileInput, fileNameDisplay) {
  dropArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropArea.classList.add('dragover');
  });

  dropArea.addEventListener('dragleave', () => {
    dropArea.classList.remove('dragover');
  });

  dropArea.addEventListener('drop', (e) => {
    e.preventDefault();
    dropArea.classList.remove('dragover');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      fileInput.files = files;
      fileNameDisplay.textContent = `Selected: ${files[0].name}`;
      updateUploadButtonState();
    }
  });
}


// --- Behavior auth ---
tokenInput.addEventListener('input', () => {
  const token = tokenInput.value.trim();

  if (token === '') {
    tokenInput.classList.remove('invalid');
    return;
  }

  if (isValidToken(token)) {
    tokenInput.classList.remove('invalid');
    storeToken(token);
    tokenInput.value = '';
    swapActionArea();
  } else {
    tokenInput.classList.add('invalid');
  }
});


// --- Behavior upload ---
setupDragAndDrop(uploadArea, fileUpload, fileNameDisplay);

uploadBtn.addEventListener('click', () => {
  fileUpload.click();  // fileUpload is your <input type="file">
});

textUpload.addEventListener('input', updateUploadButtonState);

fileUpload.addEventListener('change', () => {
  updateUploadButtonState();
  const file = fileUpload.files[0];
  fileNameDisplay.textContent = file ? `Selected: ${file.name}` : '';
});

btnUpload.addEventListener('click', handleUpload);

// --- PIN and Encryption functionality ---

// DOM references for overlays
const pinDialog = document.getElementById('pin');
const pinInput = document.getElementById('pinInput');
const pinOk = document.getElementById('pinOk');
const pinCancel = document.getElementById('pinCancel');
const pinErr = document.getElementById('pinErr');

const generatorOverlay = document.getElementById('generatorOverlay');
const btnGenerateUrl = document.getElementById('btnGenerateUrl');
const genInput = document.getElementById('genInput');
const genPat = document.getElementById('genPat');
const genPin = document.getElementById('genPin');
const genDo = document.getElementById('genDo');
const genOut = document.getElementById('genOut');
const genOutText = document.getElementById('genOutText');
const genCopy = document.getElementById('genCopy');

// Event listeners for overlays
btnGenerateUrl.addEventListener('click', showGeneratorDialog);
pinOk.addEventListener('click', handlePinUnlock);
pinCancel.addEventListener('click', hidePinDialog);
genDo.addEventListener('click', handleGenerateUrl);
genCopy.addEventListener('click', handleCopyUrl);

// Click outside to close overlays
generatorOverlay.addEventListener('click', (e) => {
  if (e.target === generatorOverlay) hideGeneratorOverlay();
});

pinDialog.addEventListener('click', (e) => {
  if (e.target === pinDialog) hidePinDialog();
});

// Enter key handlers
pinInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handlePinUnlock();
});

genPin.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleGenerateUrl();
});

function showPinDialog() {
  pinDialog.style.display = 'flex';
  pinInput.focus();
}

function hidePinDialog() {
  pinDialog.style.display = 'none';
  pinErr.style.display = 'none';
  pinInput.value = '';
}

function showGeneratorDialog() {
  generatorOverlay.style.display = 'flex';
}

function hideGeneratorOverlay() {
  generatorOverlay.style.display = 'none';
  genPat.value = '';
  genPin.value = '';
  genOut.style.display = 'none';
  genInput.style.display = 'block';
}

async function handlePinUnlock() {
  const pin = pinInput.value.trim();
  if (!pin) {
    showPinError('Please enter a PIN');
    return;
  }
  
  if (!window.crypto || !window.crypto.subtle) {
    showPinError('WebCrypto not available');
    return;
  }
  
  try {
    const decrypted = await decryptToken(state.encryptedData, pin);
    
    if (!isValidToken(decrypted)) {
      showPinError('Invalid token format');
      return;
    }
    
    // Store the decrypted token
    sessionStorage.setItem('gh_token', decrypted);
    state.encryptedData = null;
    
    hidePinDialog();
    swapActionArea();
  } catch (error) {
    showPinError('Wrong PIN or corrupted data');
  }
}

function showPinError(message) {
  pinErr.textContent = message;
  pinErr.style.display = 'block';
}

async function handleGenerateUrl() {
  const pat = genPat.value.trim();
  const pin = genPin.value.trim();
  
  if (!pat || !pin) {
    setStatus('Please enter both PAT and PIN', 'error');
    return;
  }
  
  if (!isValidToken(pat)) {
    setStatus('Invalid GitHub token format', 'error');
    return;
  }
  
  if (!window.crypto || !window.crypto.subtle) {
    setStatus('WebCrypto not available', 'error');
    return;
  }
  
  try {
    const encrypted = await encryptToken(pat, pin);
    const url = `${window.location.origin}${window.location.pathname}#v=1&salt=${encrypted.salt}&iv=${encrypted.iv}&ct=${encrypted.ct}&iter=${encrypted.iter}`;
    
    genOutText.value = url;
    genInput.style.display = 'none';
    genOut.style.display = 'block';
    
    // Clear inputs for security
    genPat.value = '';
    genPin.value = '';
  } catch (error) {
    setStatus('Encryption failed', 'error');
  }
}

function handleCopyUrl() {
  genOutText.select();
  document.execCommand('copy');
  setStatus('URL copied to clipboard', 'success');
}

async function encryptToken(plaintext, pin) {
  const encoder = new TextEncoder();
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const iterations = 300000;
  
  // Derive key from PIN
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  const key = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  
  // Encrypt the token
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(plaintext)
  );
  
  return {
    salt: base64UrlEncode(salt),
    iv: base64UrlEncode(iv),
    ct: base64UrlEncode(new Uint8Array(encrypted)),
    iter: iterations
  };
}

async function decryptToken(encData, pin) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  
  const salt = base64UrlDecode(encData.salt);
  const iv = base64UrlDecode(encData.iv);
  const ct = base64UrlDecode(encData.ct);
  
  // Derive key from PIN
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  const key = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: encData.iter,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Decrypt the token
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ct
  );
  
  return decoder.decode(decrypted);
}

function base64UrlEncode(bytes) {
  // Convert bytes to string without using spread operator to avoid stack overflow
  let binaryString = '';
  for (let i = 0; i < bytes.length; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return btoa(binaryString)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  // Add padding if needed
  str += '==='.slice((str.length + 3) % 4);
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
}

function setStatus(message, type = '') {
  const statusEl = document.getElementById('uploadStatus');
  if (statusEl) {
    statusEl.textContent = message;
    statusEl.className = type;
    statusEl.classList.remove('hidden');
  }
}
