/* ============================================================
   Firewallo — Dashboard View
   Status cards, live kernel state, firewall control, system info
   ============================================================ */

async function renderDashboard() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading dashboard...'));

    async function refresh() {
        const [status, validate, version, interfaces] = await Promise.all([
            API.get('firewall/status'),
            API.get('validate'),
            API.get('version'),
            API.get('config/interfaces')
        ]);

        const s = status.data || {};
        const v = validate.data || {};
        const ver = (version.data || {}).version || '?';
        const ifaces = interfaces.data || {};
        const ifaceCount = (ifaces.lan || []).length + (ifaces.wan || []).length +
                           (ifaces.dmz || []).length + (ifaces.vpn || []).length;
        const liveSysctl = s.live_sysctl || {};

        view.innerHTML = '';
        view.appendChild(createPageHeader('Dashboard', 'System overview and quick actions \u2014 auto-refreshes every 5s'));

        // Stats
        const stats = html('div', { className: 'stats-grid' });
        stats.appendChild(html('div', { className: 'stat-card' },
            html('div', { className: 'stat-label' }, 'Firewall Status'),
            html('div', { className: `stat-value ${s.active ? 'success' : 'danger'}` },
                s.active ? 'Active' : 'Inactive'),
            html('div', { className: 'stat-meta' }, `Backend: ${(s.backend || 'nft').toUpperCase()}`)
        ));
        stats.appendChild(html('div', { className: 'stat-card' },
            html('div', { className: 'stat-label' }, 'Backend'),
            html('div', { className: 'stat-value accent' }, (s.backend || 'nft').toUpperCase()),
            html('div', { className: 'stat-meta' }, s.backend === 'ipt' ? 'iptables' : 'nftables')
        ));
        stats.appendChild(html('div', { className: 'stat-card' },
            html('div', { className: 'stat-label' }, 'Generated Commands'),
            html('div', { className: 'stat-value accent' }, String(v.command_count || 0)),
            html('div', { className: 'stat-meta' }, v.valid ? 'Config valid' : 'Config invalid')
        ));
        stats.appendChild(html('div', { className: 'stat-card' },
            html('div', { className: 'stat-label' }, 'Interfaces'),
            html('div', { className: 'stat-value accent' }, String(ifaceCount)),
            html('div', { className: 'stat-meta' }, 'LAN / WAN / DMZ / VPN')
        ));
        view.appendChild(stats);

        // Live kernel sysctl
        const sysctlCard = html('div', { className: 'card' });
        sysctlCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'Live Kernel State')));
        const sysctlGrid = html('div', { className: 'grid grid-4' });
        function sysctlItem(label, val) {
            return html('div', {},
                html('div', { className: 'text-secondary', style: 'font-size:0.78rem' }, label),
                createBadge(val ? 'ON' : 'OFF', val ? 'success' : 'danger'));
        }
        sysctlGrid.appendChild(sysctlItem('IP Forward', liveSysctl.ip_forward));
        sysctlGrid.appendChild(sysctlItem('Dynamic Addr', liveSysctl.ip_dynaddr));
        sysctlGrid.appendChild(sysctlItem('SYN Cookies', liveSysctl.tcp_syncookies));
        sysctlGrid.appendChild(sysctlItem('Source Route', liveSysctl.accept_source_route));
        sysctlCard.appendChild(sysctlGrid);
        view.appendChild(sysctlCard);

        // Actions
        const actionsCard = html('div', { className: 'card' });
        actionsCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'Firewall Control')));
        const btnGroup = html('div', { className: 'btn-group' });
        function actionBtn(label, action, cls) {
            return html('button', {
                className: `btn ${cls}`,
                onClick: async () => {
                    const ok = await doubleConfirm(`${label} Firewall`,
                        `Are you sure you want to ${action} the firewall?`, label,
                        action === 'reset' ? 'btn-danger' : action === 'stop' ? 'btn-warning' : cls);
                    if (!ok) return;
                    const r = await API.post(`firewall/${action}`, {});
                    notify(r.error ? r.message : (r.data || {}).message || 'Done',
                           r.error ? 'error' : 'success');
                    updateHeaderStatus();
                    refresh();
                }
            }, label);
        }
        btnGroup.appendChild(actionBtn('Start', 'start', 'btn-success'));
        btnGroup.appendChild(actionBtn('Stop', 'stop', 'btn-warning'));
        btnGroup.appendChild(actionBtn('Restart', 'restart', 'btn-primary'));
        btnGroup.appendChild(actionBtn('Reset', 'reset', 'btn-danger'));
        actionsCard.appendChild(btnGroup);
        view.appendChild(actionsCard);

        // Info
        const infoCard = html('div', { className: 'card' });
        infoCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'System Information')));
        const infoGrid = html('div', { className: 'grid grid-2' });
        function infoItem(label, value) {
            return html('div', {},
                html('div', { className: 'text-secondary', style: 'font-size:0.82rem' }, label),
                html('div', { className: 'fw-600' }, value));
        }
        infoGrid.appendChild(infoItem('Version', `v${ver}`));
        infoGrid.appendChild(infoItem('Backend', (s.backend || 'nft').toUpperCase()));
        infoGrid.appendChild(infoItem('Config Valid', v.valid ? 'Yes' : 'No'));
        infoGrid.appendChild(infoItem('Commands', String(v.command_count || 0)));
        infoCard.appendChild(infoGrid);
        view.appendChild(infoCard);
    }

    await refresh();
    startPolling(refresh, 5000);
}
