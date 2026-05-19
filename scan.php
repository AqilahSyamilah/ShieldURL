<?php
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ShieldURL Scanner</title>
  <style>
    body {
      margin: 0;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f1f5f9;
    }

    .scan-wrapper {
      max-width: 760px;
      margin: 48px auto;
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.12);
      padding: 24px;
    }

    .scan-wrapper h1 {
      margin-bottom: 8px;
    }

    .scan-subtext {
      color: #4a5568;
      margin-bottom: 18px;
    }

    .scan-form {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    #urlInput {
      flex: 1;
      min-width: 260px;
      margin: 0;
    }

    .scan-btn {
      border: none;
      border-radius: 6px;
      padding: 12px 18px;
      background: #2b6cb0;
      color: #ffffff;
      font-weight: 600;
      cursor: pointer;
    }

    .scan-btn:disabled {
      opacity: 0.65;
      cursor: not-allowed;
    }

    #loadingIndicator {
      display: none;
      margin-top: 14px;
      color: #2d3748;
      font-weight: 600;
    }

    .result-box {
      margin-top: 16px;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 14px;
      background: #f7fafc;
    }

    .result-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      margin-top: 10px;
    }

    .result-item {
      background: #ffffff;
      border-radius: 6px;
      padding: 10px;
      border: 1px solid #edf2f7;
    }

    .label {
      font-size: 0.84rem;
      color: #4a5568;
      margin-bottom: 4px;
      display: block;
    }

    .status-badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 0.86rem;
    }

    .status-medium {
      color: #b7791f;
      background: #faf089;
    }

    .status-safe {
      color: #15803d;
      background: #dcfce7;
    }

    .status-phishing {
      color: #b91c1c;
      background: #fee2e2;
    }

    .error-box {
      margin-top: 14px;
      background: #fed7d7;
      color: #c53030;
      border-radius: 8px;
      padding: 10px 12px;
      display: none;
    }

  </style>
</head>
<body>
  <div class="scan-wrapper">
    <h1>ShieldURL Scan</h1>
    <p class="scan-subtext">Scan a URL using the FastAPI backend.</p>

    <form id="scanForm" class="scan-form">
      <input
        type="text"
        id="urlInput"
        name="url"
        placeholder="https://example.com"
        required
      >
      <button type="submit" class="scan-btn" id="scanBtn">Scan URL</button>
    </form>

    <div id="loadingIndicator">Scanning URL...</div>
    <div id="errorBox" class="error-box"></div>

    <div id="resultBox" class="result-box" style="display:none;">
      <div><span class="label">Overall Verdict</span><span id="overallVerdict"></span></div>
      <div class="result-grid">
        <div class="result-item"><span class="label">ML Status</span><span id="mlStatus"></span></div>
        <div class="result-item"><span class="label">ML Confidence Score</span><span id="mlConfidence"></span></div>
        <div class="result-item"><span class="label">ML Risk Level</span><span id="mlRisk"></span></div>
        <div class="result-item"><span class="label">Detection Sensitivity</span><span id="selectedThreshold"></span></div>
        <div class="result-item"><span class="label">System Detection</span><span id="machineVerdict"></span></div>
        <div class="result-item"><span class="label">Safety Status</span><span id="displayVerdict"></span></div>
        <div class="result-item"><span class="label">PhishTank In Database</span><span id="ptInDb"></span></div>
        <div class="result-item"><span class="label">PhishTank Verified</span><span id="ptVerified"></span></div>
        <div class="result-item"><span class="label">PhishTank Is Phishing</span><span id="ptPhishing"></span></div>
      </div>
      <div class="result-item" style="margin-top:10px;">
        <span class="label">How ShieldURL Decides</span>
        <span id="modelPolicy">The system uses advanced URL detection analysis to identify suspicious website patterns.</span>
      </div>
    </div>
  </div>

  <script>
    const scanForm = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const errorBox = document.getElementById('errorBox');
    const resultBox = document.getElementById('resultBox');

    function toBadgeClass(value) {
      const text = String(value || '').toLowerCase();
      if (text.includes('phish')) return 'status-phishing';
      if (text.includes('safe')) return 'status-safe';
      return 'status-medium';
    }

    function renderBadge(targetId, value) {
      const el = document.getElementById(targetId);
      const cls = toBadgeClass(value);
      el.innerHTML = '<span class="status-badge ' + cls + '">' + String(value) + '</span>';
    }

    function renderText(targetId, value) {
      const el = document.getElementById(targetId);
      el.textContent = String(value);
    }

    function formatProbability(value) {
      const number = Number(value);
      if (!Number.isFinite(number)) return 'N/A';
      const percent = number <= 1 ? number * 100 : number;
      return percent.toFixed(2) + '%';
    }

    function simplePolicyText(value) {
      const text = String(value || '').trim();
      if (!text || /lexical model|false negatives|threshold|recall/i.test(text)) {
        return 'The system uses advanced URL detection analysis to identify suspicious website patterns.';
      }
      return text;
    }

    function renderBool(targetId, value) {
      if (typeof value !== 'boolean') {
        renderText(targetId, 'N/A');
        return;
      }
      renderText(targetId, value ? 'true' : 'false');
    }

    scanForm.addEventListener('submit', async function (event) {
      event.preventDefault();

      const url = urlInput.value.trim();
      if (!url) {
        errorBox.textContent = 'Please enter a URL.';
        errorBox.style.display = 'block';
        resultBox.style.display = 'none';
        return;
      }

      errorBox.style.display = 'none';
      resultBox.style.display = 'none';
      loadingIndicator.style.display = 'block';
      scanBtn.disabled = true;

      try {
        const response = await fetch('http://127.0.0.1:8000/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ url: url, clicked: false })
        });

        const text = await response.text();
        console.log('Raw response:', text);

        let data;
        try {
          data = JSON.parse(text);
        } catch (error) {
          throw new Error('Backend did not return valid JSON: ' + text);
        }

        if (!response.ok) {
          throw new Error(
            data?.error ||
            data?.detail ||
            data?.message ||
            ('Backend returned HTTP ' + response.status)
          );
        }

        renderBadge('overallVerdict', data?.overall?.display_verdict ?? data?.overall?.verdict ?? 'N/A');
        renderBadge('mlStatus', data?.ml?.status ?? 'N/A');
        renderText('mlConfidence', formatProbability(data?.ml?.phishing_probability ?? data?.ml?.confidence_score));
        renderBadge('mlRisk', data?.ml?.risk_level ?? 'N/A');
        renderText('selectedThreshold', formatProbability(data?.ml?.selected_threshold));
        renderText('machineVerdict', data?.overall?.status ?? data?.detection?.final_verdict ?? 'N/A');
        renderText('displayVerdict', data?.overall?.display_verdict ?? data?.detection?.display_verdict ?? 'N/A');
        renderText('modelPolicy', simplePolicyText(data?.ml?.model_policy ?? data?.overall?.model_policy));
        renderBool('ptInDb', data?.phishtank?.in_database);
        renderBool('ptVerified', data?.phishtank?.verified);
        renderBool('ptPhishing', data?.phishtank?.is_phishing);

        resultBox.style.display = 'block';
      } catch (err) {
        errorBox.textContent = 'Scan failed: ' + (err.message || 'Unknown error');
        errorBox.style.display = 'block';
      } finally {
        loadingIndicator.style.display = 'none';
        scanBtn.disabled = false;
      }
    });
  </script>
</body>
</html>
