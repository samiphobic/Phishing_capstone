const API = 'https://phishguard-qcxq.onrender.com/analyze';

const urlInput   = document.getElementById('urlInput');
const scanBtn    = document.getElementById('scanBtn');
const errMsg     = document.getElementById('errMsg');
const resultCard = document.getElementById('resultCard');
const currentUrl = document.getElementById('currentUrl');

async function getCurrentTabUrl() {
  return new Promise(resolve => {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        resolve(tabs && tabs[0] ? tabs[0].url : '');
      });
    } catch {
      resolve('');
    }
  });
}

async function scan(url) {
  errMsg.textContent = '';

  if (!url || url.trim() === '') {
    errMsg.textContent = 'Enter a URL first.';
    return;
  }

  scanBtn.textContent = '...';
  scanBtn.disabled    = true;
  resultCard.style.display = 'none';
  currentUrl.textContent = 'Scanning...';

  try {
    const res  = await fetch(API, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url: url.trim() }),
    });

    if (!res.ok) {
      errMsg.textContent = 'Server error. Try again.';
      return;
    }

    const data = await res.json();

    if (data.error) {
      errMsg.textContent = data.error;
      return;
    }

    render(data);

  } catch (e) {
    errMsg.textContent = 'Cannot reach server. Check connection or wait 30s for server to wake up.';
  } finally {
    scanBtn.textContent = 'Scan';
    scanBtn.disabled    = false;
    currentUrl.textContent = url.trim();
  }
}

function render(data) {
  const score = data.risk_score;

  const color = score >= 7 ? '#f87171'
              : score >= 4 ? '#fbbf24'
              : '#34d399';

  const numEl = document.getElementById('scoreNum');
  numEl.textContent = score + '/10';
  numEl.style.color = color;

  document.getElementById('scoreLabel').textContent = data.risk_level || '';
  document.getElementById('scoreSub').textContent   = data.explanation || '';

  const grid    = document.getElementById('featGrid');
  const entries = Object.entries(data.feature_analysis || {});

  grid.innerHTML = entries.map(([k, v]) => `
    <div class="feat-cell ${v.warning ? 'warn' : 'ok'}">
      <div class="feat-key">${k}</div>
      <div class="feat-val">${v.value}</div>
    </div>
  `).join('');

  resultCard.style.display = 'block';
}

scanBtn.addEventListener('click', () => {
  scan(urlInput.value);
});

urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') scan(urlInput.value);
});

async function init() {
  try {
    const tabUrl = await getCurrentTabUrl();
    if (tabUrl && (tabUrl.startsWith('http://') || tabUrl.startsWith('https://'))) {
      urlInput.value = tabUrl;
      currentUrl.textContent = 'Current tab detected';
      scan(tabUrl);
    } else {
      currentUrl.textContent = 'Enter any URL to scan';
    }
  } catch {
    currentUrl.textContent = 'Enter any URL to scan';
  }
}

init();
