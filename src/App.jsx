import React, { useState } from 'react';
import FileDropZone from './components/FileDropZone';
import { scanFile } from './services/api';

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async (file) => {
    setLoading(true);
    setError("");
    try {
      const data = await scanFile(file);
      setResult(data);
    } catch (err) {
      setError("Gagal memindai file. Coba lagi.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-purple-900 text-white">
      <div className="container mx-auto px-4 py-12 max-w-3xl">
        <div className="text-center mb-10">
          <h1 className="text-4xl font-bold mb-3">🛡️ SentinelAI WebGuard</h1>
          <p className="text-purple-200">
            Antivirus berbasis cloud — aman, cepat, tanpa instalasi.
          </p>
        </div>

        <div className="bg-gray-800/50 backdrop-blur-sm rounded-2xl p-6 shadow-xl border border-gray-700">
          <FileDropZone onScan={handleScan} />

          {loading && (
            <div className="mt-6 text-center">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
              <p className="mt-3">Memindai file dengan AI...</p>
            </div>
          )}

          {error && <p className="mt-4 text-red-400 text-center">{error}</p>}

          {result && (
            <div className="mt-8 bg-gray-900/70 rounded-xl p-5 border border-gray-600">
              <h2 className="text-xl font-bold mb-3">📊 Hasil Pemindaian</h2>
              <p><strong>File:</strong> {result.filename}</p>
              <p><strong>Hash:</strong> {result.file_hash}</p>
              
              {result.scan_result.is_malicious ? (
                <div className="mt-4 p-4 bg-red-900/30 border border-red-700 rounded-lg">
                  <p className="text-red-300">⚠️ Ancaman Terdeteksi!</p>
                  <p><strong>Jenis:</strong> {result.scan_result.threat_name}</p>
                  <p><strong>Risiko:</strong> {result.scan_result.risk_level}</p>
                  <p><strong>Keyakinan:</strong> {(result.scan_result.confidence * 100).toFixed(1)}%</p>
                </div>
              ) : (
                <div className="mt-4 p-4 bg-green-900/30 border border-green-700 rounded-lg">
                  <p className="text-green-300">✅ File aman!</p>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="mt-12 text-center text-sm text-gray-400">
          <p>Data file tidak disimpan. Analisis dilakukan di cloud dan dihapus setelah 1 menit.</p>
          <p className="mt-2">© 2025 SentinelAI. Semua hak dilindungi.</p>
        </div>
      </div>
    </div>
  );
        }
