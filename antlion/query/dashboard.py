"""
High-fidelity SOC Web Dashboard UI for Antlion Threat Intelligence & Intrusion Detection.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antlion | Defensive Threat Intelligence & Honeypot Pit Console</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg: #090d16;
            --surface: #111827;
            --surface-border: #1f293d;
            --accent: #06b6d4;
            --accent-glow: rgba(6, 182, 212, 0.2);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --success: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
        body { background: var(--bg); color: var(--text-main); min-height: 100vh; padding: 1.5rem 2rem; }
        
        /* Header */
        header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--surface-border); padding-bottom: 1.2rem; margin-bottom: 1.5rem; }
        .brand { display: flex; align-items: center; gap: 0.8rem; }
        .brand-icon { font-size: 1.8rem; }
        .brand-title { font-size: 1.4rem; font-weight: 800; letter-spacing: 0.5px; }
        .brand-badge { background: rgba(6, 182, 212, 0.15); color: var(--accent); padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; border: 1px solid var(--accent); }
        .live-status { display: flex; align-items: center; gap: 0.6rem; font-size: 0.85rem; color: var(--text-muted); }
        .pulse-dot { width: 10px; height: 10px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }

        /* Metrics Row */
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.2rem; margin-bottom: 1.5rem; }
        .metric-card { background: var(--surface); border: 1px solid var(--surface-border); border-radius: 8px; padding: 1.2rem; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }
        .metric-label { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 0.4rem; }
        .metric-val { font-size: 1.9rem; font-weight: 800; color: var(--text-main); }
        .metric-sub { font-size: 0.75rem; color: var(--accent); margin-top: 0.3rem; }

        /* Charts Row */
        .charts-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 1.2rem; margin-bottom: 1.5rem; }
        @media(max-width: 900px) { .charts-grid { grid-template-columns: 1fr; } }
        .chart-card { background: var(--surface); border: 1px solid var(--surface-border); border-radius: 8px; padding: 1.2rem; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .card-title { font-size: 0.95rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }

        /* Table Section */
        .feed-card { background: var(--surface); border: 1px solid var(--surface-border); border-radius: 8px; padding: 1.2rem; }
        .feed-controls { display: flex; gap: 0.8rem; align-items: center; }
        .btn-refresh { background: #1e293b; color: white; border: 1px solid #334155; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem; }
        .btn-refresh:hover { background: #334155; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }
        th { text-align: left; padding: 0.7rem; color: var(--text-muted); border-bottom: 1px solid var(--surface-border); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
        td { padding: 0.75rem 0.7rem; border-bottom: 1px solid #1a2234; }
        tr:hover { background: rgba(255,255,255,0.02); }

        /* Badges */
        .badge { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
        .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .badge-HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
        .badge-MEDIUM { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .badge-LOW { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
        
        .ip-link { color: var(--accent); cursor: pointer; text-decoration: underline; font-weight: 600; }
        .ip-link:hover { color: #67e8f9; }

        /* Modal */
        .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.75); display: none; align-items: center; justify-content: center; z-index: 100; backdrop-filter: blur(4px); }
        .modal { background: #111827; border: 1px solid var(--surface-border); border-radius: 8px; width: 650px; max-width: 90vw; padding: 1.8rem; box-shadow: 0 10px 30px rgba(0,0,0,0.8); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--surface-border); padding-bottom: 0.8rem; margin-bottom: 1rem; }
        .btn-close { background: none; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; }
        .dossier-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.8rem; margin-bottom: 1.2rem; font-size: 0.85rem; }
        .dossier-item { background: #0f172a; padding: 0.6rem; border-radius: 4px; border: 1px solid #1e293b; }
        .dossier-key { color: var(--text-muted); font-size: 0.75rem; }
        .dossier-val { color: var(--text-main); font-weight: 600; margin-top: 0.2rem; }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <span class="brand-icon">🐜🦁</span>
            <div class="brand-title">ANTLION</div>
            <span class="brand-badge">SOC PIT CONSOLE</span>
        </div>
        <div class="live-status">
            <div class="pulse-dot"></div>
            <span>DEFENSIVE HONEYPOT PIT ACTIVE</span>
            <span id="last-updated" style="margin-left: 1rem; font-size: 0.75rem;"></span>
        </div>
    </header>

    <!-- Top Metrics -->
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Total Threat Verdicts</div>
            <div class="metric-val" id="total-verdicts">0</div>
            <div class="metric-sub">Multi-Signal Fused</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Decoy Pit Hits</div>
            <div class="metric-val" id="total-decoy-hits">0</div>
            <div class="metric-sub">Web & SSH Traps</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Monitored Flows</div>
            <div class="metric-val" id="total-flows">0</div>
            <div class="metric-sub">CIC-IDS2017 Format</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Top Threat Severity</div>
            <div class="metric-val" id="peak-severity" style="color: var(--high);">LOW</div>
            <div class="metric-sub">Active Risk Posture</div>
        </div>
    </div>

    <!-- Charts -->
    <div class="charts-grid">
        <div class="chart-card">
            <div class="card-header">
                <div class="card-title">Attack Family Classification Breakdown</div>
            </div>
            <canvas id="attackChart" height="110"></canvas>
        </div>
        <div class="chart-card">
            <div class="card-header">
                <div class="card-title">Threat Severity Distribution</div>
            </div>
            <canvas id="severityChart" height="220"></canvas>
        </div>
    </div>

    <!-- Live Verdicts Feed -->
    <div class="feed-card">
        <div class="card-header">
            <div class="card-title">Live Honeypot Pit Intrusion Feed</div>
            <div class="feed-controls">
                <button class="btn-refresh" onclick="fetchData()">⟳ Refresh Feed</button>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Decoy Target</th>
                    <th>Attack Family</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody id="verdicts-table-body">
                <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Loading telemetry...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- IP Dossier Modal -->
    <div class="modal-overlay" id="ipModal">
        <div class="modal">
            <div class="modal-header">
                <h3 id="modalIpTitle" style="color: var(--accent);">Attacker Threat Dossier</h3>
                <button class="btn-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="dossier-grid" id="modalDossierBody">
                <!-- Dynamically populated -->
            </div>
            <h4 style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem; text-transform: uppercase;">Recent Forensic Activity:</h4>
            <div id="modalTimeline" style="max-height: 200px; overflow-y: auto; font-size: 0.8rem; background: #0b0f19; padding: 0.8rem; border-radius: 4px; border: 1px solid #1f293d;">
            </div>
        </div>
    </div>

    <script>
        let attackChart = null;
        let severityChart = null;

        async function fetchData() {
            try {
                const [statsRes, verdictsRes] = await Promise.all([
                    fetch('/api/v1/stats'),
                    fetch('/api/v1/verdicts?limit=25')
                ]);
                const stats = await statsRes.json();
                const verdicts = await verdictsRes.json();

                updateMetrics(stats);
                updateCharts(stats);
                renderTable(verdicts);
                document.getElementById('last-updated').innerText = 'Synced: ' + new Date().toLocaleTimeString();
            } catch (err) {
                console.error("Failed fetching Antlion telemetry:", err);
            }
        }

        function updateMetrics(stats) {
            document.getElementById('total-verdicts').innerText = stats.total_verdicts || 0;
            document.getElementById('total-decoy-hits').innerText = stats.total_decoy_hits || 0;
            document.getElementById('total-flows').innerText = stats.total_flows_monitored || 0;

            const sevBreakdown = stats.severity_breakdown || {};
            const peakSev = sevBreakdown.CRITICAL ? 'CRITICAL' : (sevBreakdown.HIGH ? 'HIGH' : (sevBreakdown.MEDIUM ? 'MEDIUM' : 'LOW'));
            const peakEl = document.getElementById('peak-severity');
            peakEl.innerText = peakSev;
            peakEl.style.color = peakSev === 'CRITICAL' ? 'var(--critical)' : (peakSev === 'HIGH' ? 'var(--high)' : 'var(--medium)');
        }

        function updateCharts(stats) {
            const attackData = stats.attack_type_breakdown || {};
            const attackLabels = Object.keys(attackData);
            const attackCounts = Object.values(attackData);

            if (attackChart) attackChart.destroy();
            const ctx1 = document.getElementById('attackChart').getContext('2d');
            attackChart = new Chart(ctx1, {
                type: 'bar',
                data: {
                    labels: attackLabels.length ? attackLabels : ['No data'],
                    datasets: [{
                        label: 'Interactions',
                        data: attackCounts.length ? attackCounts : [0],
                        backgroundColor: '#06b6d4',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { ticks: { color: '#9ca3af' }, grid: { color: '#1f293d' } },
                        x: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { display: false } }
                    }
                }
            });

            const sevData = stats.severity_breakdown || {};
            if (severityChart) severityChart.destroy();
            const ctx2 = document.getElementById('severityChart').getContext('2d');
            severityChart = new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    datasets: [{
                        data: [sevData.CRITICAL || 0, sevData.HIGH || 0, sevData.MEDIUM || 0, sevData.LOW || 0],
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af', font: { size: 11 } } } }
                }
            });
        }

        function renderTable(verdicts) {
            const tbody = document.getElementById('verdicts-table-body');
            if (!verdicts || !verdicts.length) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No threat activity recorded yet. Connect to the decoys to trigger alerts.</td></tr>';
                return;
            }

            tbody.innerHTML = verdicts.map(v => {
                const ts = v.timestamp.replace('T', ' ').substring(0, 19);
                return `
                    <tr>
                        <td style="color: var(--text-muted);">${ts}</td>
                        <td><span class="ip-link" onclick="openIpDossier('${v.source_ip}')">${v.source_ip}</span></td>
                        <td><code>${v.target_service}</code></td>
                        <td>${v.attack_type}</td>
                        <td><span class="badge badge-${v.severity}">${v.severity}</span></td>
                        <td><strong>${(v.confidence * 100).toFixed(0)}%</strong></td>
                        <td><button class="btn-refresh" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;" onclick="openIpDossier('${v.source_ip}')">Dossier</button></td>
                    </tr>
                `;
            }).join('');
        }

        async function openIpDossier(ip) {
            try {
                const res = await fetch(`/api/v1/intel/${ip}`);
                const data = await res.json();
                document.getElementById('modalIpTitle').innerText = 'Threat Intelligence Dossier: ' + ip;
                
                const body = document.getElementById('modalDossierBody');
                body.innerHTML = `
                    <div class="dossier-item"><div class="dossier-key">TOTAL VERDICTS</div><div class="dossier-val">${data.total_verdicts}</div></div>
                    <div class="dossier-item"><div class="dossier-key">TOTAL DECOY HITS</div><div class="dossier-val">${data.total_decoy_hits}</div></div>
                    <div class="dossier-item"><div class="dossier-key">PEAK SEVERITY</div><div class="dossier-val badge badge-${data.highest_severity}">${data.highest_severity}</div></div>
                    <div class="dossier-item"><div class="dossier-key">ATTACK TYPES OBSERVED</div><div class="dossier-val">${data.observed_attack_types.join(', ') || 'N/A'}</div></div>
                `;

                const timeline = document.getElementById('modalTimeline');
                const interactions = data.recent_decoy_interactions || [];
                if (interactions.length) {
                    timeline.innerHTML = interactions.map(item => `
                        <div style="margin-bottom: 0.5rem; border-left: 2px solid var(--accent); padding-left: 0.5rem;">
                            <span style="color: var(--text-muted);">${item.timestamp.substring(0, 19)}</span> - 
                            <strong>${item.target_service}</strong> (${item.depth})
                            <div>${item.username ? 'Creds: <code>' + item.username + '</code>' : ''} ${item.http_path ? 'Path: <code>' + item.http_path + '</code>' : ''}</div>
                        </div>
                    `).join('');
                } else {
                    timeline.innerHTML = '<div style="color: var(--text-muted);">No interactive command history available.</div>';
                }

                document.getElementById('ipModal').style.display = 'flex';
            } catch (err) {
                console.error("Failed opening IP dossier:", err);
            }
        }

        function closeModal() {
            document.getElementById('ipModal').style.display = 'none';
        }

        // Initialize and setup 5s polling
        fetchData();
        setInterval(fetchData, 5000);
    </script>
</body>
</html>
"""
