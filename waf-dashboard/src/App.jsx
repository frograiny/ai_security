import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, ShieldCheck, Activity, 
  Server, Cpu, WifiOff, Globe
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  Cell, LineChart, Line, CartesianGrid 
} from 'recharts';

// API WAF Endpoint
const API_URL = 'http://localhost:5000/ai-waf/stats';

function App() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [feed, setFeed] = useState([]);

  // Fetch API every 2 seconds
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(API_URL);
        if (!res.ok) throw new Error('API Error');
        const data = await res.json();
        setStats(data);
        setError(null);
        
        // Update timeline logic
        const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit'});
        setTimeline(prev => {
          const newPoint = { time: now, requests: data.traffic.total_requests, blocked: data.traffic.total_blocked };
          const newTimeline = [...prev, newPoint];
          return newTimeline.length > 20 ? newTimeline.slice(1) : newTimeline;
        });

        // Mock Real-time Threat Feed based on blocks_by_type updates
        // In a real app with WebSockets, to emulate here we use blocks changes
      } catch (err) {
        setError('Connection to WAF failed');
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 2000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) return <div style={{color: 'white', padding: '2rem'}}>Loading WAF Shield...</div>;

  const dataBlocks = stats ? Object.keys(stats.traffic.blocks_by_type).map(type => ({
    name: type,
    value: stats.traffic.blocks_by_type[type]
  })) : [];

  const colors = ['#00e0ff', '#ff0055', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#14b8a6', '#f43f5e'];

  return (
    <div className="dashboard-container">
      <header className="dashboard-header glass-panel">
        <div className="logo-container" style={{padding: '1rem'}}>
          <Shield className="logo-icon" size={32} />
          <div>
            <h1 className="title">AI WAF SHIELD</h1>
            <div className="subtitle">Enterprise Deep-Learning Protection</div>
          </div>
        </div>
        <div style={{padding: '1rem'}}>
          {error ? (
            <div className="status-badge" style={{color: 'var(--danger)', background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239,68,68,0.2)'}}>
              <WifiOff size={16} /> OFFLINE
            </div>
          ) : (
            <div className="status-badge">
              <div className="status-dot"></div> ONLINE (Bi-LSTM Active)
            </div>
          )}
        </div>
      </header>

      <div className="metrics-grid">
        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span className="metric-title">Total Requests</span>
            <Globe size={20} className="color-accent-1" />
          </div>
          <div className="metric-value">{stats?.traffic.total_requests || 0}</div>
          <div className="metric-subvalue">Scanned by AI Engine</div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span className="metric-title">Threats Blocked</span>
            <ShieldCheck size={20} className="color-success" />
          </div>
          <div className="metric-value color-danger">{stats?.traffic.total_blocked || 0}</div>
          <div className="metric-subvalue">Block Rate: {stats?.traffic.block_rate || '0%'}</div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span className="metric-title">Rule Blacklist</span>
            <AlertTriangle size={20} className="color-accent-2" />
          </div>
          <div className="metric-value">{stats?.blacklist.active_blacklisted || 0}</div>
          <div className="metric-subvalue">IPs Banned Currently</div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span className="metric-title">System Status</span>
            <Server size={20} className={stats?.backend === 'healthy' ? "color-success" : "color-danger"} />
          </div>
          <div className="metric-value" style={{fontSize: '1.5rem', marginTop: '0.5rem', textTransform: 'capitalize'}}>{stats?.backend || 'Unknown'}</div>
          <div className="metric-subvalue">Cache Hits: {stats?.cache.hit_rate || '0%'}</div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-card glass-panel">
          <h3 className="chart-title"><Activity size={18} /> Network Traffic (Live)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} tickMargin={10} />
              <YAxis stroke="#94a3b8" fontSize={12} />
              <Tooltip 
                contentStyle={{ backgroundColor: 'rgba(10, 14, 23, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
                itemStyle={{ color: '#fff' }}
              />
              <Line type="monotone" dataKey="requests" stroke="var(--accent-primary)" strokeWidth={2} dot={false} animationDuration={300} />
              <Line type="monotone" dataKey="blocked" stroke="var(--accent-secondary)" strokeWidth={2} dot={false} animationDuration={300} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card glass-panel live-feed-card">
          <h3 className="chart-title"><AlertTriangle size={18} /> Attack Distribution</h3>
          {dataBlocks.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={dataBlocks} layout="vertical" margin={{ top: 0, right: 30, left: 20, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="#f8fafc" fontSize={12} width={100} axisLine={false} tickLine={false} />
                <Tooltip cursor={{fill: 'rgba(255,255,255,0.05)'}} contentStyle={{ backgroundColor: 'rgba(10,14,23,0.9)', border: 'none', borderRadius: '8px' }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20} animationDuration={500}>
                  {dataBlocks.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{display:'flex', alignItems:'center', justifyContent:'center', height:'100%', color: 'var(--text-muted)'}}>
              No attacks detected yet
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
