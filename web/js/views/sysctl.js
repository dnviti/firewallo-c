/* ============================================================
   Firewallo — Sysctl View
   Kernel network parameters and backend switch
   ============================================================ */

async function renderSysctl() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading sysctl settings...'));

    async function refresh() {
        const [cfgRes, statusRes] = await Promise.all([
            API.get('config'),
            API.get('firewall/status')
        ]);
        const cfg = cfgRes.data || {};
        const sysctl = cfg.sysctl || {};
        const liveStatus = statusRes.data || {};
        const liveSysctl = liveStatus.live_sysctl || {};

        view.innerHTML = '';
        view.appendChild(createPageHeader('Sysctl Settings', 'Kernel network parameters \u2014 live system state'));

        const settings = [
            { key: 'ip_forward', label: 'IP Forwarding', desc: 'Enable packet forwarding between interfaces (net.ipv4.ip_forward)' },
            { key: 'ip_dynaddr', label: 'Dynamic Address', desc: 'Support for dynamic IP addresses on interfaces (net.ipv4.ip_dynaddr)' },
            { key: 'tcp_syncookies', label: 'TCP SYN Cookies', desc: 'Protect against SYN flood attacks (net.ipv4.tcp_syncookies)' },
            { key: 'accept_source_route', label: 'Accept Source Route', desc: 'Accept packets with source routing (net.ipv4.conf.all.accept_source_route)' }
        ];

        const card = html('div', { className: 'card' });
        card.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'Configuration vs Live Kernel')));

        settings.forEach(s => {
            const cfgVal = !!sysctl[s.key];
            const liveVal = !!liveSysctl[s.key];
            const mismatch = cfgVal !== liveVal;
            const row = html('div', { className: 'flex items-center justify-between',
                style: 'padding:12px 0; border-bottom:1px solid var(--border)' });
            const info = html('div', { style: 'flex:1' },
                html('div', { className: 'fw-600' }, s.label),
                html('div', { className: 'text-secondary', style: 'font-size:0.82rem' }, s.desc),
                html('div', { className: 'flex items-center gap-8 mt-4', style: 'font-size:0.78rem' },
                    html('span', {}, 'Live kernel: '),
                    createBadge(liveVal ? 'ON' : 'OFF', liveVal ? 'success' : 'danger'),
                    mismatch ? createBadge('MISMATCH', 'warning') : null));
            const toggle = html('label', { className: 'toggle' });
            const checkbox = html('input', { type: 'checkbox' });
            checkbox.checked = cfgVal;
            checkbox.addEventListener('change', async () => {
                const ok = await doubleConfirm(`Change ${s.label}`,
                    `Set ${s.label} to ${checkbox.checked ? 'enabled' : 'disabled'} in config?`, 'Save', 'btn-primary');
                if (!ok) { checkbox.checked = !checkbox.checked; return; }
                const r = await API.mutateConfig(c => { if (!c.sysctl) c.sysctl = {}; c.sysctl[s.key] = checkbox.checked; });
                notify(r.ok ? `${s.label} ${checkbox.checked ? 'enabled' : 'disabled'}` : r.message, r.ok ? 'success' : 'error');
                if (!r.ok) checkbox.checked = !checkbox.checked;
                else refresh();
            });
            toggle.appendChild(checkbox);
            toggle.appendChild(html('span', { className: 'toggle-slider' }));
            row.appendChild(info);
            row.appendChild(toggle);
            card.appendChild(row);
        });

        card.appendChild(html('div', { className: 'text-muted mt-8', style: 'font-size:0.78rem' },
            'Note: Config changes are saved to firewallo.json. Live kernel values are applied when the firewall is started/restarted.'));
        view.appendChild(card);

        // Backend switch
        const backendCard = html('div', { className: 'card mt-16' });
        backendCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'Firewall Backend')));
        const currentBackend = cfg.backend || 'nft';
        const backendSelect = formSelect([
            { value: 'nft', label: 'nftables (nft)', selected: currentBackend === 'nft' },
            { value: 'ipt', label: 'iptables (ipt)', selected: currentBackend === 'ipt' }
        ], { style: 'width:200px' });
        const saveBtn = html('button', {
            className: 'btn btn-primary btn-sm',
            onClick: async () => {
                const val = backendSelect.value;
                if (val === currentBackend) { notify('Backend unchanged', 'warning'); return; }
                const ok = await doubleConfirm('Switch Backend',
                    `Switch from ${currentBackend.toUpperCase()} to ${val.toUpperCase()}?`, 'Switch', 'btn-warning');
                if (!ok) { backendSelect.value = currentBackend; return; }
                const r = await API.put('config/backend', { backend: val });
                notify(r.error ? r.message : 'Backend updated', r.error ? 'error' : 'success');
                updateHeaderStatus();
                if (!r.error) refresh();
            }
        }, 'Save');
        const frow = html('div', { className: 'form-row' });
        frow.appendChild(formField('Backend Engine', backendSelect, 'Switch between nftables and iptables'));
        frow.appendChild(html('div', { className: 'form-group' },
            html('label', { className: 'form-label' }, '\u00A0'), saveBtn));
        backendCard.appendChild(frow);
        view.appendChild(backendCard);
    }

    await refresh();
    startPolling(refresh, 5000);
}
