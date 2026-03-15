/* ============================================================
   Firewallo — Network View
   System interfaces (live), zone assignment, DNS, IP ranges
   ============================================================ */

async function renderInterfaces() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading interfaces...'));

    async function refresh() {
        const [cfgRes, sysRes] = await Promise.all([
            API.get('config'),
            API.get('system/interfaces')
        ]);
        const cfg = cfgRes.data || {};
        const ifaces = cfg.interfaces || {};
        const sysIfaces = sysRes.error ? [] : (sysRes.data || []);
        const sysNames = sysIfaces.map(i => i.name);

        view.innerHTML = '';
        view.appendChild(createPageHeader('Interfaces',
            'System network interfaces and zone assignment \u2014 live'));

        // ── System Interfaces card (live from OS) ──
        const sysCard = html('div', { className: 'card' });
        sysCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'System Interfaces'),
            createBadge(String(sysIfaces.length), 'accent')
        ));

        if (sysIfaces.length > 0) {
            const rows = sysIfaces.map(iface => {
                const ips = (iface.addresses || [])
                    .filter(a => a.family === 'ipv4')
                    .map(a => a.address)
                    .join(', ') || '-';
                return [
                    html('span', { className: 'fw-600 mono' }, iface.name),
                    createBadge(iface.state.toUpperCase(),
                        iface.state === 'up' ? 'success' : iface.state === 'down' ? 'danger' : 'neutral'),
                    createBadge(iface.type_name, 'accent'),
                    html('span', { className: 'mono' }, iface.mac || '-'),
                    String(iface.mtu || '-'),
                    iface.speed > 0 ? `${iface.speed} Mbps` : '-',
                    html('span', { className: 'mono' }, ips),
                    formatBytes(iface.stats ? iface.stats.rx_bytes : 0),
                    formatBytes(iface.stats ? iface.stats.tx_bytes : 0)
                ];
            });
            sysCard.appendChild(createFilterableTable(
                ['Name', 'Status', 'Type', 'MAC', 'MTU', 'Speed', 'IPv4', 'RX', 'TX'],
                rows, { searchPlaceholder: 'Search interfaces...' }
            ));
        } else {
            sysCard.appendChild(html('div', { className: 'empty-state' },
                html('div', { className: 'empty-state-text' },
                    'Could not read system interfaces')));
        }
        view.appendChild(sysCard);

        // ── Zone assignment cards ──
        const zones = [
            { key: 'lan', label: 'LAN Interfaces', max: 8 },
            { key: 'wan', label: 'WAN Interfaces', max: 8 },
            { key: 'dmz', label: 'DMZ Interfaces', max: 8 },
            { key: 'vpn', label: 'VPN Interfaces', max: 8 }
        ];

        zones.forEach(zone => {
            const items = ifaces[zone.key] || [];
            view.appendChild(createEditableList({
                title: zone.label,
                items,
                maxItems: zone.max,
                placeholder: 'e.g. eth0, ens18, tun0',
                suggestions: sysNames,
                validator: val => {
                    if (!/^[a-zA-Z][a-zA-Z0-9._-]*$/.test(val)) {
                        notify('Invalid interface name', 'error'); return false;
                    }
                    return true;
                },
                onAdd: async (val) => {
                    const ok = await doubleConfirm('Add Interface',
                        `Add "${val}" to ${zone.label}?`, 'Add');
                    if (!ok) return;
                    const r = await API.mutateConfig(c => {
                        if (!c.interfaces) c.interfaces = {};
                        if (!c.interfaces[zone.key]) c.interfaces[zone.key] = [];
                        if (c.interfaces[zone.key].includes(val)) throw new Error('Already exists');
                        c.interfaces[zone.key].push(val);
                    });
                    notify(r.ok ? 'Interface added' : r.message, r.ok ? 'success' : 'error');
                    if (r.ok) refresh();
                },
                onRemove: async (val) => {
                    const ok = await doubleConfirm('Remove Interface',
                        `Remove "${val}" from ${zone.label}?`, 'Remove', 'btn-danger');
                    if (!ok) return;
                    const r = await API.mutateConfig(c => {
                        const arr = (c.interfaces || {})[zone.key] || [];
                        const idx = arr.indexOf(val);
                        if (idx >= 0) arr.splice(idx, 1);
                    });
                    notify(r.ok ? 'Interface removed' : r.message, r.ok ? 'success' : 'error');
                    if (r.ok) refresh();
                }
            }));
        });
    }

    await refresh();
    startPolling(refresh, 5000);
}

async function renderDns() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading DNS servers...'));

    async function refresh() {
        const res = await API.get('config');
        const cfg = res.data || {};
        const servers = cfg.dns_servers || [];

        view.innerHTML = '';
        view.appendChild(createPageHeader('DNS Servers', 'Manage DNS resolver addresses'));

        view.appendChild(createEditableList({
            title: 'DNS Servers',
            items: servers,
            maxItems: 8,
            placeholder: 'e.g. 8.8.8.8',
            validator: val => {
                if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) {
                    notify('Invalid IPv4 address', 'error'); return false;
                }
                return true;
            },
            onAdd: async (val) => {
                const ok = await doubleConfirm('Add DNS Server',
                    `Add "${val}" to DNS servers?`, 'Add');
                if (!ok) return;
                const r = await API.mutateConfig(c => {
                    if (!c.dns_servers) c.dns_servers = [];
                    if (c.dns_servers.includes(val)) throw new Error('Already exists');
                    c.dns_servers.push(val);
                });
                notify(r.ok ? 'DNS server added' : r.message, r.ok ? 'success' : 'error');
                if (r.ok) refresh();
            },
            onRemove: async (val) => {
                const ok = await doubleConfirm('Remove DNS Server',
                    `Remove "${val}" from DNS servers?`, 'Remove', 'btn-danger');
                if (!ok) return;
                const r = await API.mutateConfig(c => {
                    const idx = (c.dns_servers || []).indexOf(val);
                    if (idx >= 0) c.dns_servers.splice(idx, 1);
                });
                notify(r.ok ? 'DNS server removed' : r.message, r.ok ? 'success' : 'error');
                if (r.ok) refresh();
            }
        }));
    }

    await refresh();
    startPolling(refresh, 5000);
}

async function renderRanges() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading IP ranges...'));

    async function refresh() {
        const res = await API.get('config');
        const cfg = res.data || {};
        const ranges = cfg.ranges || {};

        view.innerHTML = '';
        view.appendChild(createPageHeader('IP Ranges', 'Manage LAN and DMZ network ranges'));

        [{ key: 'lan', label: 'LAN Ranges' }, { key: 'dmz', label: 'DMZ Ranges' }].forEach(zone => {
            const items = ranges[zone.key] || [];
            view.appendChild(createEditableList({
                title: zone.label,
                items,
                maxItems: 16,
                placeholder: 'e.g. 192.168.1.0/24',
                validator: val => {
                    if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(val)) {
                        notify('Invalid CIDR notation (e.g. 10.0.0.0/24)', 'error'); return false;
                    }
                    return true;
                },
                onAdd: async (val) => {
                    const ok = await doubleConfirm('Add Range',
                        `Add "${val}" to ${zone.label}?`, 'Add');
                    if (!ok) return;
                    const r = await API.mutateConfig(c => {
                        if (!c.ranges) c.ranges = {};
                        if (!c.ranges[zone.key]) c.ranges[zone.key] = [];
                        if (c.ranges[zone.key].includes(val)) throw new Error('Already exists');
                        c.ranges[zone.key].push(val);
                    });
                    notify(r.ok ? 'Range added' : r.message, r.ok ? 'success' : 'error');
                    if (r.ok) refresh();
                },
                onRemove: async (val) => {
                    const ok = await doubleConfirm('Remove Range',
                        `Remove "${val}" from ${zone.label}?`, 'Remove', 'btn-danger');
                    if (!ok) return;
                    const r = await API.mutateConfig(c => {
                        const arr = (c.ranges || {})[zone.key] || [];
                        const idx = arr.indexOf(val);
                        if (idx >= 0) arr.splice(idx, 1);
                    });
                    notify(r.ok ? 'Range removed' : r.message, r.ok ? 'success' : 'error');
                    if (r.ok) refresh();
                }
            }));
        });
    }

    await refresh();
    startPolling(refresh, 5000);
}
