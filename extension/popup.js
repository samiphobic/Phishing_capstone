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
      <div class="feat-key">
        ${k}
        <button class="info-icon" data-info="${k}">i</button>
      </div>
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

const infoData = {
   "URL length": "How long the URL is. Long URLs often hide malicious parameters or redirect chains.",
  "Encryption": "HTTPS indicates encryption which protects your information. However, attackers can still get certificates, so it's not a guarantee of safety.",
  "TLD": "The ending of the URL like .com or .org. Uncommon TLDs can be a red flag as they are abused more frequently.",
  "Subdomains": "Many subdomains can indicate deceptive URL structures.",
  "Entropy": "High entropy suggests randomness, often used to evade detection.",
  "@ symbol": "Presence of '@' can hide the real domain.", 
  "Keywords": "Suspicious words like 'login', 'secure', 'update' in the URL can indicate phishing.", 
  "Domain type":"The category the TLD belongs to, some types are more commonly used for phishing than others."
};


document.addEventListener("click", (e) => {
  if (e.target.classList.contains("info-icon")) {
    const key = e.target.dataset.info;
    document.getElementById("infoTitle").textContent = key;
    document.getElementById("infoText").textContent = infoData[key] || "No info available.";
    document.getElementById("infoPanel").style.display = "block";
  }
});

document.getElementById("clearBtn").addEventListener("click", () => {
  urlInput.value = "";
  errMsg.textContent = "";
  resultCard.style.display = "none";
  document.getElementById("infoPanel").style.display = "none";
});
