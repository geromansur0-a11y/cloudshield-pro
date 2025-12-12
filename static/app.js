class CloudShieldPro {
  constructor() {
    this.isDark = localStorage.getItem('darkMode') === 'true';
    this.history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
    this.init();
  }

  init() {
    this.applyTheme();
    document.getElementById('themeToggle')?.addEventListener('click', () => this.toggleTheme());
    document.getElementById('scanBtn')?.addEventListener('click', () => this.scan());
    document.getElementById('scanUrlBtn')?.addEventListener('click', () => this.scanUrl());
    this.renderHistory();
  }

  applyTheme() {
    if (this.isDark) {
      document.body.classList.add('dark');
      document.getElementById('themeToggle')?.setAttribute('data-icon', '☀️');
    } else {
      document.body.classList.remove('dark');
      document.getElementById('themeToggle')?.setAttribute('data-icon', '🌙');
    }
    document.getElementById('themeToggle')?.textContent = 
      document.getElementById('themeToggle')?.getAttribute('data-icon') || '🌙';
  }

  toggleTheme() {
    this.isDark = !this.isDark;
    localStorage.setItem('darkMode', this.isDark);
    this.applyTheme();
  }

  async scan() {
    const file = document.getElementById('fileInput').files[0];
    if (!file) return alert('Pilih file dulu!');
    
    const btn = document.getElementById('scanBtn');
    btn.disabled = true;
    btn.textContent = 'Memindai...';

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/scan', {
        method: 'POST',
        body: formData,
        headers: { 'X-Forwarded-For': '127.0.0.1' }
      });
      const data = await res.json();
      this.showResult(data);
      this.saveToHistory(data);
    } catch (err) {
      alert('Error: ' + (err.message || err));
    } finally {
      btn.disabled = false;
      btn.textContent = 'Scan File';
    }
  }

  async scanUrl() {
    const url = document.getElementById('urlInput').value;
    if (!url) return alert('Masukkan URL dulu!');
    
    const btn = document.getElementById('scanUrlBtn');
    btn.disabled = true;
    btn.textContent = 'Mengunduh & Memindai...';

    try {
      const res = await fetch('/scan-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(url)}`
      });
      const data = await res.json();
      this.showResult(data);
      this.saveToHistory(data);
    } catch (err) {
      alert('Error: ' + (err.message || err));
    } finally {
      btn.disabled = false;
      btn.textContent = '🔍 Scan dari URL';
    }
  }

  showResult(data) {
    const riskColor = { low: 'green', medium: 'orange', high: 'red', critical: 'darkred' };
    const status = data.malicious 
      ? `<span style="color:${riskColor[data.risk]}">⚠️ ${data.risk.toUpperCase()}</span>`
      : `<span style="color:green">✅ AMAN</span>`;

    let metadataHtml = '';
    if (Object.keys(data.metadata).length > 0) {
      metadataHtml = `<h4>Metadata:</h4><ul>`;
      for (const [key, value] of Object.entries(data.metadata)) {
        metadataHtml += `<li><strong>${key}:</strong> ${value}</li>`;
      }
      metadataHtml += `</ul>`;
    }

    const findingsHtml = data.findings.length 
      ? `<ul>${data.findings.map(f => `<li>${f}</li>`).join('')}</ul>`
      : '<p>Tidak ada ancaman ditemukan.</p>';

    document.getElementById('result').innerHTML = `
      <div class="result">
        <h3>🔍 Hasil Analisis</h3>
        <p><strong>File:</strong> ${data.filename}</p>
        <p><strong>Status:</strong> ${status}</p>
        <p><strong>Ukuran:</strong> ${(data.file_size / 1024).toFixed(1)} KB</p>
        <p><strong>Hash:</strong> ${data.hash?.substring(0, 16)}...</p>
        ${metadataHtml}
        <h4>Temuan:</h4>
        ${findingsHtml}
        <button onclick="cloudshield.exportPDF(${JSON.stringify(data)})">📄 Simpan sebagai PDF</button>
        <button onclick="cloudshield.exportJSON(${JSON.stringify(data)})">💾 Simpan sebagai JSON</button>
      </div>
    `;
  }

  exportPDF(data) {
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
      <html><head><title>Laporan CloudShield</title></head><body>
        <h2>CloudShield Pro - Laporan Scan</h2>
        <p><strong>File:</strong> ${data.filename}</p>
        <p><strong>Status:</strong> ${data.malicious ? 'BERBAHAYA' : 'AMAN'}</p>
        <p><strong>Risiko:</strong> ${data.risk}</p>
        <p><strong>Waktu:</strong> ${data.scan_time}</p>
        <h3>Metadata:</h3>
        <ul>${Object.entries(data.metadata).map(([k,v]) => `<li><strong>${k}:</strong> ${v}</li>`).join('')}</ul>
        <h3>Temuan:</h3>
        <ul>${data.findings.map(f => `<li>${f}</li>`).join('')}</ul>
        <p><em>Dibuat di CloudShield Pro - ${new Date().toLocaleString()}</em></p>
      </body></html>
    `);
    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
    printWindow.close();
  }

  exportJSON(data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cloudshield-report-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  saveToHistory(scan) {
    this.history.unshift({ ...scan, timestamp: new Date().toISOString() });
    this.history = this.history.slice(0, 10);
    localStorage.setItem('scanHistory', JSON.stringify(this.history));
    this.renderHistory();
  }

  renderHistory() {
    const container = document.getElementById('historyList');
    if (!container) return;
    container.innerHTML = `
      <h3>Riwayat Scan</h3>
      ${this.history.map(item => `
        <div class="history-item">
          <span class="${item.malicious ? 'malicious' : 'safe'}">${item.malicious ? '❌' : '✅'}</span>
          ${item.filename} <small>(${new Date(item.timestamp).toLocaleTimeString()})</small>
        </div>
      `).join('')}
    `;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.cloudshield = new CloudShieldPro();
});
