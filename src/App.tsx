// src/App.tsx
import React, { useState, useEffect } from 'react';

interface Country {
  name: string;
  code: string;
  flag: string;
  ip: string;
}

export default function App() {
  const [userInfo, setUserInfo] = useState<string>('Not Logged In');
  const [token, setToken] = useState<string>(localStorage.getItem('token') || '');
  const [userCode, setUserCode] = useState<string>('');
  const [countries, setCountries] = useState<Country[]>([]);
  const [selectedCountry, setSelectedCountry] = useState<string>('');
  const [vpnStatus, setVpnStatus] = useState<string>('Status: Disconnected');

  useEffect(() => {
    async function init() {
      if (token) {
        try {
          const res = await fetch('/api/whoami', { headers: { 'Authorization': `Bearer ${token}` } });
          if (res.ok) {
            const data = await res.json();
            setUserInfo(`Logged in: ${data.email || data.user_id}`);
          }
        } catch (e) {
          console.error(e);
        }
      }

      try {
        const countryRes = await fetch('/api/vpn/countries');
        const data = await countryRes.json();
        const list: Country[] = Array.isArray(data) ? data : (data.countries || []);
        setCountries(list);
        if (list.length > 0) setSelectedCountry(list[0].code);
      } catch (e) {
        console.error(e);
      }
    }
    init();
  }, [token]);

  const connectDevice = async () => {
    if (!token) {
      alert('Please log in first.');
      return;
    }
    const res = await fetch('/api/device/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ user_code: userCode })
    });
    const data = await res.json();
    alert(data.message || data.error);
  };

  const connectVpn = async () => {
    if (!token) {
      alert('Please log in first.');
      return;
    }
    const res = await fetch('/api/vpn/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ country_code: selectedCountry })
    });
    const data = await res.json();
    if (res.ok) {
      setVpnStatus(`Connected: ${data.flag} ${data.country} (${data.ip})`);
    } else {
      alert(data.error || 'Failed to connect VPN');
    }
  };

  const disconnectVpn = async () => {
    await fetch('/api/vpn/disconnect', { method: 'POST', headers: { 'Authorization': `Bearer ${token}` } });
    setVpnStatus('Status: Disconnected');
  };

  return (
    <div className="bg-slate-900 text-slate-100 min-h-screen p-6 font-sans">
      <div className="max-w-4xl mx-auto space-y-6">
        <header className="border-b border-slate-800 pb-4 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">VPN & OAuth Gateway</h1>
            <p className="text-sm text-slate-400">React Vite TypeScript Frontend (Port 5900 Configured)</p>
          </div>
          <div className="text-sm bg-slate-800 px-3 py-1.5 rounded border border-slate-700">{userInfo}</div>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-800 p-5 rounded-lg border border-slate-700 space-y-4">
            <h2 className="text-lg font-semibold">Device Authorization Flow</h2>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Enter Device Code</label>
              <input 
                type="text" 
                placeholder="e.g., A2B4" 
                value={userCode} 
                onChange={(e) => setUserCode(e.target.value)} 
                className="w-full bg-slate-900 border border-slate-700 p-2 rounded text-sm uppercase text-slate-100" 
              />
            </div>
            <button onClick={connectDevice} className="w-full bg-indigo-600 hover:bg-indigo-500 py-2.5 rounded font-medium transition text-sm">Connect Account</button>
          </div>

          <div className="bg-slate-800 p-5 rounded-lg border border-slate-700 space-y-4">
            <h2 className="text-lg font-semibold">VPN Control Center</h2>
            <div className="text-sm bg-slate-900 p-3 rounded border border-slate-700 text-slate-300">{vpnStatus}</div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Select VPN Country</label>
              <select 
                value={selectedCountry} 
                onChange={(e) => setSelectedCountry(e.target.value)} 
                className="w-full bg-slate-900 border border-slate-700 p-2 rounded text-sm text-slate-100"
              >
                {Array.isArray(countries) && countries.map(c => (
                  <option key={c.code} value={c.code}>{c.flag} {c.name} ({c.ip})</option>
                ))}
              </select>
            </div>
            <div className="flex gap-2">
              <button onClick={connectVpn} className="flex-1 bg-emerald-600 hover:bg-emerald-500 py-2.5 rounded font-medium transition text-sm">Connect VPN</button>
              <button onClick={disconnectVpn} className="flex-1 bg-rose-600 hover:bg-rose-500 py-2.5 rounded font-medium transition text-sm">Disconnect</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
