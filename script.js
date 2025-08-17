// Always clear stored token on page load
window.addEventListener('load', () => {
  sessionStorage.clear();
});

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

// --- DOM References auth ---
const tokenInput = document.getElementById('tokenInput');
const authArea = document.getElementById('authArea');
const actionArea = document.getElementById('actionArea');

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

// --- DOM References upload ---
const textUpload = document.getElementById('textInput');
const fileUpload = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const btnUpload = document.getElementById('btnUploadContent');
const fileNameDisplay = document.getElementById('fileName');
const uploadArea = document.getElementById('uploadArea');


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


