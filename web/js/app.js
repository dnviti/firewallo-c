/* ============================================================
   Firewallo Web Application
   SPA router, views, theme management, sidebar behavior
   ============================================================ */

var view = document.getElementById('view');
var pageTitle = document.getElementById('page-title');

var routes = {
    dashboard: { render: renderDashboard, title: 'Dashboard' },
    filter: { render: renderFilter, title: 'Filter Rules' },
    nat: { render: renderNat, title: 'NAT' },
    vpn: { render: renderVpn, title: 'VPN' },
    config: { render: renderConfig, title: 'Configuration' },
    logs: { render: renderLogs, title: 'Rules' }
};

/* --- Theme Management --- */
(function initTheme() {
    var saved = localStorage.getItem('firewallo-theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
    }
})();

document.getElementById('theme-toggle').addEventListener('click', function() {
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.classList.add('theme-transitioning');
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('firewallo-theme', next);
    setTimeout(function() {
        document.documentElement.classList.remove('theme-transitioning');
    }, 350);
});

/* --- Sidebar --- */
(function initSidebar() {
    var sidebar = document.getElementById('sidebar');
    var collapseBtn = document.getElementById('sidebar-collapse-btn');
    var hamburgerBtn = document.getElementById('hamburger-btn');

    var collapsed = localStorage.getItem('firewallo-sidebar-collapsed') === 'true';
    if (collapsed) sidebar.classList.add('collapsed');

    collapseBtn.addEventListener('click', function() {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('firewallo-sidebar-collapsed', sidebar.classList.contains('collapsed'));
    });

    hamburgerBtn.addEventListener('click', function() {
        sidebar.classList.toggle('mobile-open');
    });

    // Close mobile sidebar on nav click
    sidebar.querySelectorAll('.nav-item').forEach(function(item) {
        item.addEventListener('click', function() {
            if (window.innerWidth <= 768) {
                sidebar.classList.remove('mobile-open');
            }
        });
    });
})();

/* --- Status Indicator --- */
async function updateStatus() {
    var indicator = document.getElementById('status-indicator');
    var res = await API.get('firewall/status');
    if (res.error || !res.data) {
        indicator.className = 'status-indicator offline';
        indicator.querySelector('.status-text').textContent = 'Error';
        return;
    }
    var s = res.data;
    if (s.active) {
        indicator.className = 'status-indicator online';
        indicator.querySelector('.status-text').textContent = 'Active';
    } else {
        indicator.className = 'status-indicator offline';
        indicator.querySelector('.status-text').textContent = 'Inactive';
    }
}

// Update status periodically
updateStatus();
setInterval(updateStatus, 15000);

/* --- Version in sidebar --- */
(async function loadVersion() {
    var res = await API.get('version');
    if (res.error || !res.data) return;
    var ver = res.data.version || '';
    var el = document.getElementById('sidebar-version');
    if (el && ver) el.textContent = 'v' + ver;
})();

/* ============================================================
   Views
   ============================================================ */

// --- Dashboard ---
async function renderDashboard() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading dashboard...'));

    var results = await Promise.all([
        API.get('firewall/status'),
        API.get('validate'),
        API.get('version'),
        API.get('filter')
    ]);
    var status = results[0];
    var validate = results[1];
    var version = results[2];
    var filter = results[3];

    var s = status.data || {};
    var v = validate.data || {};
    var chains = filter.data || {};

    // Count total interfaces (estimate from chain info)
    var chainKeys = Object.keys(chains);
    var totalPorts = 0;
    chainKeys.forEach(function(k) {
        var c = chains[k];
        totalPorts += (c.tcp_count || 0) + (c.udp_count || 0);
    });

    view.innerHTML = '';

    // Stat cards
    var statGrid = html('div', { className: 'stat-grid' });
    statGrid.appendChild(createStatCard(
        s.active ? 'Active' : 'Inactive',
        'Firewall Status',
        s.active ? 'success' : 'danger',
        '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7v6c0 5.5 4.3 10.3 10 11 5.7-.7 10-5.5 10-11V7L12 2z"/></svg>'
    ));
    statGrid.appendChild(createStatCard(
        (s.backend || 'nft').toUpperCase(),
        'Backend',
        'info',
        '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>'
    ));
    statGrid.appendChild(createStatCard(
        String(v.command_count || 0),
        'Generated Rules',
        'accent',
        '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>'
    ));
    statGrid.appendChild(createStatCard(
        String(totalPorts),
        'Open Ports',
        'warning',
        '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>'
    ));
    view.appendChild(statGrid);

    // Quick actions
    var actionsCard = html('div', { className: 'card' });
    var actionsHeader = html('div', { className: 'card-header' });
    actionsHeader.appendChild(html('h3', {}, 'Quick Actions'));
    actionsCard.appendChild(actionsHeader);

    var btnGroup = html('div', { className: 'btn-group' });
    var actions = [
        { name: 'start', label: 'Start', cls: 'btn btn-success', icon: '\u25B6' },
        { name: 'stop', label: 'Stop', cls: 'btn btn-danger', icon: '\u25A0' },
        { name: 'restart', label: 'Restart', cls: 'btn btn-primary', icon: '\u21BB' },
        { name: 'reset', label: 'Reset', cls: 'btn btn-danger', icon: '\u26A0' }
    ];

    actions.forEach(function(action) {
        var btn = html('button', { className: action.cls }, action.icon + ' ' + action.label);
        btn.addEventListener('click', function() {
            var msg = action.name === 'reset'
                ? 'This will flush all firewall rules and reset to defaults. Are you sure?'
                : 'Are you sure you want to ' + action.name + ' the firewall?';
            var confirmCls = action.name === 'reset' || action.name === 'stop'
                ? 'btn btn-danger' : 'btn btn-primary';
            showConfirm(
                action.label + ' Firewall',
                msg,
                async function() {
                    var r = await API.post('firewall/' + action.name, {});
                    notify(r.error ? r.message : (r.data || {}).message || 'Done',
                           r.error ? 'error' : 'success');
                    updateStatus();
                    renderDashboard();
                },
                action.label,
                confirmCls
            );
        });
        btnGroup.appendChild(btn);
    });
    actionsCard.appendChild(btnGroup);
    view.appendChild(actionsCard);

    // Validation and version info
    var infoGrid = html('div', { className: 'grid grid-2' });

    var valCard = html('div', { className: 'card' });
    var valHeader = html('div', { className: 'card-header' });
    valHeader.appendChild(html('h3', {}, 'Validation'));
    valCard.appendChild(valHeader);
    var validBadge = v.valid
        ? html('span', { className: 'badge badge-success' }, 'Valid')
        : html('span', { className: 'badge badge-danger' }, 'Invalid');
    valCard.appendChild(html('div', { className: 'flex items-center gap-3' },
        validBadge,
        html('span', { className: 'mono', style: 'color:var(--text-secondary)' },
            (v.command_count || 0) + ' commands generated')
    ));
    if (v.errors && v.errors.length > 0) {
        valCard.appendChild(html('div', { className: 'mt-3' }));
        v.errors.forEach(function(err) {
            valCard.appendChild(html('p', {
                style: 'color:var(--danger);font-size:0.85rem;margin-top:4px'
            }, err));
        });
    }
    infoGrid.appendChild(valCard);

    var verCard = html('div', { className: 'card' });
    var verHeader = html('div', { className: 'card-header' });
    verHeader.appendChild(html('h3', {}, 'System'));
    verCard.appendChild(verHeader);
    verCard.appendChild(html('p', {}, 'Firewallo ' + ((version.data || {}).version || '?')));
    verCard.appendChild(html('p', {
        className: 'mono mt-2',
        style: 'color:var(--text-muted);font-size:0.82rem'
    }, 'Backend: ' + (s.backend || 'nft') + ' | Config: ' + (v.valid ? 'OK' : 'errors')));
    infoGrid.appendChild(verCard);

    view.appendChild(infoGrid);
}

// --- Filter Rules ---
async function renderFilter() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading filter chains...'));

    var res = await API.get('filter');
    var chains = res.data || {};

    view.innerHTML = '';

    var zones = [
        { key: 'fw', label: 'FW' },
        { key: 'lan', label: 'LAN' },
        { key: 'wan', label: 'WAN' },
        { key: 'dmz', label: 'DMZ' },
        { key: 'vpns', label: 'VPN' }
    ];

    // Count rules per source zone for tab badges
    zones.forEach(function(z) {
        var count = 0;
        zones.forEach(function(dst) {
            var name = z.key + '2' + dst.key;
            var info = chains[name] || {};
            count += (info.tcp_count || 0) + (info.udp_count || 0) + (info.rule_count || 0);
        });
        z.count = count;
    });

    var tabContainer = createTabBar(zones, function(zoneKey, contentArea) {
        renderFilterZone(zoneKey, zones, chains, contentArea);
    });

    view.appendChild(tabContainer);
}

function renderFilterZone(srcZone, zones, chains, container) {
    container.innerHTML = '';

    var desc = html('p', { className: 'section-desc mb-4' },
        'Traffic originating from zone ' + srcZone.toUpperCase() + ' to other zones');
    container.appendChild(desc);

    // Chain grid for this source zone
    var grid = html('div', { className: 'chain-grid', style: 'margin-bottom:20px' });
    zones.forEach(function(dst) {
        var name = srcZone + '2' + dst.key;
        var info = chains[name] || { tcp_count: 0, udp_count: 0, rule_count: 0 };
        var total = (info.tcp_count || 0) + (info.udp_count || 0) + (info.rule_count || 0);
        var cls = total > 0 ? 'chain-cell has-rules' : 'chain-cell';
        var cell = html('div', { className: cls },
            html('div', { className: 'name' }, dst.label),
            html('div', { className: 'count' },
                (info.tcp_count || 0) + ' TCP / ' + (info.udp_count || 0) + ' UDP')
        );
        cell.addEventListener('click', function() {
            renderChainDetail(name);
        });
        grid.appendChild(cell);
    });
    container.appendChild(grid);

    // Table of all chains for this zone
    var tableRows = [];
    zones.forEach(function(dst) {
        var name = srcZone + '2' + dst.key;
        var info = chains[name] || {};
        var tcpCount = info.tcp_count || 0;
        var udpCount = info.udp_count || 0;
        var ruleCount = info.rule_count || 0;
        var total = tcpCount + udpCount + ruleCount;

        var statusBadge = total > 0
            ? html('span', { className: 'badge badge-success' }, total + ' rules')
            : html('span', { className: 'badge badge-muted' }, 'Empty');

        var viewBtn = html('button', { className: 'btn btn-sm' }, 'View');
        viewBtn.addEventListener('click', function() { renderChainDetail(name); });

        tableRows.push([
            name,
            srcZone.toUpperCase(),
            dst.label,
            String(tcpCount),
            String(udpCount),
            statusBadge,
            viewBtn
        ]);
    });

    var table = createFilterableTable(
        ['Chain', 'From', 'To', 'TCP', 'UDP', 'Status', 'Action'],
        tableRows,
        'Filter chains...'
    );
    container.appendChild(table);
}

// --- Chain Detail ---
async function renderChainDetail(name) {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading chain ' + name + '...'));

    var res = await API.get('filter/' + name);
    var chain = res.data || {};

    view.innerHTML = '';

    // Breadcrumb / back
    var topBar = html('div', { className: 'flex items-center gap-3 mb-4' });
    var backBtn = html('button', { className: 'btn btn-ghost btn-sm' }, '\u2190 Back to Filter');
    backBtn.addEventListener('click', renderFilter);
    topBar.appendChild(backBtn);
    topBar.appendChild(html('h2', { style: 'margin:0' }, 'Chain: ' + name));
    view.appendChild(topBar);

    // TCP Ports
    var tcpCard = html('div', { className: 'card' });
    var tcpHeader = html('div', { className: 'card-header' });
    tcpHeader.appendChild(html('h3', {}, 'TCP Ports'));
    tcpHeader.appendChild(html('span', { className: 'badge badge-accent' },
        (chain.tcp_ports || []).length + ' ports'));
    tcpCard.appendChild(tcpHeader);

    var tcpPorts = chain.tcp_ports || [];
    if (tcpPorts.length > 0) {
        var portList = html('div', { className: 'port-list' });
        tcpPorts.forEach(function(p) {
            portList.appendChild(createPortTag(p, function(port) {
                showConfirm('Remove TCP Port', 'Remove port ' + port + ' from ' + name + '?',
                    async function() {
                        var r = await API.del('filter/' + name + '/tcp/' + port);
                        notify(r.error ? r.message : 'Port removed', r.error ? 'error' : 'success');
                        renderChainDetail(name);
                    }, 'Remove', 'btn btn-danger');
            }));
        });
        tcpCard.appendChild(portList);
    } else {
        tcpCard.appendChild(html('p', { style: 'color:var(--text-muted)' }, 'No TCP ports configured'));
    }
    view.appendChild(tcpCard);

    // UDP Ports
    var udpCard = html('div', { className: 'card' });
    var udpHeader = html('div', { className: 'card-header' });
    udpHeader.appendChild(html('h3', {}, 'UDP Ports'));
    udpHeader.appendChild(html('span', { className: 'badge badge-info' },
        (chain.udp_ports || []).length + ' ports'));
    udpCard.appendChild(udpHeader);

    var udpPorts = chain.udp_ports || [];
    if (udpPorts.length > 0) {
        var uPortList = html('div', { className: 'port-list' });
        udpPorts.forEach(function(p) {
            uPortList.appendChild(createPortTag(p, function(port) {
                showConfirm('Remove UDP Port', 'Remove port ' + port + ' from ' + name + '?',
                    async function() {
                        var r = await API.del('filter/' + name + '/udp/' + port);
                        notify(r.error ? r.message : 'Port removed', r.error ? 'error' : 'success');
                        renderChainDetail(name);
                    }, 'Remove', 'btn btn-danger');
            }));
        });
        udpCard.appendChild(uPortList);
    } else {
        udpCard.appendChild(html('p', { style: 'color:var(--text-muted)' }, 'No UDP ports configured'));
    }
    view.appendChild(udpCard);

    // Add port form
    var addCard = html('div', { className: 'card' });
    var addHeader = html('div', { className: 'card-header' });
    addHeader.appendChild(html('h3', {}, 'Add Port'));
    addCard.appendChild(addHeader);

    var portInput = html('input', {
        type: 'number',
        placeholder: 'Port (1-65535)',
        min: '1',
        max: '65535',
        style: 'width:160px'
    });
    var protoSelect = html('select', {},
        html('option', { value: 'tcp' }, 'TCP'),
        html('option', { value: 'udp' }, 'UDP'));
    var addBtn = html('button', { className: 'btn btn-primary' }, 'Add Port');
    addBtn.addEventListener('click', async function() {
        var port = parseInt(portInput.value);
        if (!port || port < 1 || port > 65535) {
            notify('Invalid port number (1-65535)', 'error');
            return;
        }
        var proto = protoSelect.value;
        var r = await API.post('filter/' + name + '/' + proto, { port: port });
        notify(r.error ? r.message : (r.data || {}).message || 'Port added',
               r.error ? 'error' : 'success');
        renderChainDetail(name);
    });

    // Enter key support
    portInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') addBtn.click();
    });

    var formRow = html('div', { className: 'form-row' });
    formRow.appendChild(portInput);
    formRow.appendChild(protoSelect);
    formRow.appendChild(addBtn);
    addCard.appendChild(formRow);
    view.appendChild(addCard);
}

// --- NAT ---
async function renderNat() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading NAT rules...'));

    var res = await API.get('nat');
    var nat = res.data || {};

    view.innerHTML = '';

    var postRules = nat.postrouting || [];
    var preRules = nat.prerouting || [];

    var tabs = [
        { key: 'postrouting', label: 'Postrouting', count: postRules.length },
        { key: 'prerouting', label: 'Prerouting', count: preRules.length }
    ];

    var tabContainer = createTabBar(tabs, function(key, contentArea) {
        contentArea.innerHTML = '';
        if (key === 'postrouting') {
            renderNatPostrouting(postRules, contentArea);
        } else {
            renderNatPrerouting(preRules, contentArea);
        }
    });
    view.appendChild(tabContainer);
}

function renderNatPostrouting(rules, container) {
    container.appendChild(html('p', { className: 'section-desc mb-4' },
        'Source NAT rules for outbound traffic (MASQUERADE / SNAT)'));

    if (rules.length > 0) {
        var rows = rules.map(function(r) {
            var typeBadge;
            if (r.type === 'masquerade' || r.type === 'MASQUERADE') {
                typeBadge = html('span', { className: 'badge badge-accent' }, r.type);
            } else if (r.type === 'snat' || r.type === 'SNAT') {
                typeBadge = html('span', { className: 'badge badge-warning' }, r.type);
            } else {
                typeBadge = html('span', { className: 'badge badge-muted' }, r.type || 'N/A');
            }
            return [r.src || '-', r.oif || '-', typeBadge, r.comment || '-'];
        });
        var table = createFilterableTable(
            ['Source', 'Out Interface', 'Type', 'Comment'],
            rows, 'Search postrouting...');
        container.appendChild(table);
    } else {
        container.appendChild(createEmptyState(
            'No postrouting rules configured. NAT masquerade is auto-generated from LAN ranges.'));
    }
}

function renderNatPrerouting(rules, container) {
    container.appendChild(html('p', { className: 'section-desc mb-4' },
        'Destination NAT rules for inbound port forwarding (DNAT)'));

    if (rules.length > 0) {
        var rows = rules.map(function(r) {
            var protoBadge = html('span', { className: 'badge badge-info' },
                (r.protocol || 'tcp').toUpperCase());
            return [
                r.iif || '-',
                protoBadge,
                String(r.dport || '-'),
                r.to_dest_ip || '-',
                String(r.to_dest_port || '-'),
                r.comment || '-'
            ];
        });
        var table = createFilterableTable(
            ['In Interface', 'Protocol', 'Port', 'Dest IP', 'Dest Port', 'Comment'],
            rows, 'Search prerouting...');
        container.appendChild(table);
    } else {
        container.appendChild(createEmptyState('No prerouting rules configured.'));
    }
}

// --- Configuration ---
async function renderConfig() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading configuration...'));

    var res = await API.get('config');
    var cfg = res.data || {};

    view.innerHTML = '';

    var tabs = [
        { key: 'sections', label: 'Sections' },
        { key: 'raw', label: 'Raw JSON' }
    ];

    var tabContainer = createTabBar(tabs, function(key, contentArea) {
        contentArea.innerHTML = '';
        if (key === 'sections') {
            renderConfigSections(cfg, contentArea);
        } else {
            renderConfigRaw(cfg, contentArea);
        }
    });
    view.appendChild(tabContainer);
}

function renderConfigSections(cfg, container) {
    // Helper: render a flat key-value list
    function renderFields(parentObj, fields) {
        var content = html('div');
        fields.forEach(function(field) {
            var value = parentObj[field];
            if (value === undefined) return;
            var row = html('div', { className: 'flex justify-between items-center', style: 'padding:8px 0;border-bottom:1px solid var(--border)' });
            row.appendChild(html('span', { className: 'form-label', style: 'margin:0;text-transform:none' }, field));
            if (typeof value === 'boolean') {
                row.appendChild(html('span', { className: value ? 'badge badge-success' : 'badge badge-muted' },
                    value ? 'Enabled' : 'Disabled'));
            } else if (Array.isArray(value)) {
                row.appendChild(html('span', { className: 'mono' }, value.join(', ') || '(none)'));
            } else {
                row.appendChild(html('span', { className: 'mono' }, String(value)));
            }
            content.appendChild(row);
        });
        return content;
    }

    // General section (top-level keys)
    var generalCollapse = createCollapsible('General', function() {
        return renderFields(cfg, ['version', 'language', 'backend']);
    }, true);
    container.appendChild(generalCollapse);

    // Interfaces section (nested under cfg.interfaces)
    var ifCollapse = createCollapsible('Interfaces', function() {
        var ifaces = cfg.interfaces || {};
        return renderFields(ifaces, Object.keys(ifaces));
    }, false);
    container.appendChild(ifCollapse);

    // DNS section (cfg.dns_servers is an array)
    var dnsCollapse = createCollapsible('DNS', function() {
        var content = html('div');
        var servers = cfg.dns_servers || [];
        var row = html('div', { className: 'flex justify-between items-center', style: 'padding:8px 0;border-bottom:1px solid var(--border)' });
        row.appendChild(html('span', { className: 'form-label', style: 'margin:0;text-transform:none' }, 'dns_servers'));
        row.appendChild(html('span', { className: 'mono' }, servers.join(', ') || '(none)'));
        content.appendChild(row);
        return content;
    }, false);
    container.appendChild(dnsCollapse);

    // Network Ranges section (nested under cfg.ranges)
    var rangesCollapse = createCollapsible('Network Ranges', function() {
        var ranges = cfg.ranges || {};
        return renderFields(ranges, Object.keys(ranges));
    }, false);
    container.appendChild(rangesCollapse);

    // Sysctl section (nested under cfg.sysctl)
    var sysctlCollapse = createCollapsible('Sysctl', function() {
        var sysctl = cfg.sysctl || {};
        return renderFields(sysctl, Object.keys(sysctl));
    }, false);
    container.appendChild(sysctlCollapse);

    // Filter chains section
    var filterChainsObj = cfg.filter || {};
    var chainCount = Object.keys(filterChainsObj).length;
    var chainCollapse = createCollapsible('Filter Chains (' + chainCount + ')', function() {
        var content = html('div');
        var zones = ['fw', 'lan', 'wan', 'dmz', 'vpns'];
        var filterCfg = cfg.filter || {};
        zones.forEach(function(src) {
            zones.forEach(function(dst) {
                var name = src + '2' + dst;
                var chain = filterCfg[name] || {};
                var tcp = chain.tcp_ports || [];
                var udp = chain.udp_ports || [];
                if (tcp.length === 0 && udp.length === 0) return;
                var row = html('div', { style: 'padding:8px 0;border-bottom:1px solid var(--border)' });
                row.appendChild(html('span', { style: 'font-weight:600;margin-right:12px' }, name));
                if (tcp.length > 0) {
                    row.appendChild(html('span', { className: 'badge badge-accent', style: 'margin-right:6px' },
                        'TCP: ' + tcp.join(', ')));
                }
                if (udp.length > 0) {
                    row.appendChild(html('span', { className: 'badge badge-info' },
                        'UDP: ' + udp.join(', ')));
                }
                content.appendChild(row);
            });
        });
        if (content.children.length === 0) {
            content.appendChild(html('p', { style: 'color:var(--text-muted)' }, 'No filter chains with configured ports'));
        }
        return content;
    }, false);
    container.appendChild(chainCollapse);

    // NAT section
    var natCollapse = createCollapsible('NAT', function() {
        var content = html('div');
        var natCfg = cfg.nat || {};
        var post = natCfg.postrouting || [];
        var pre = natCfg.prerouting || [];
        content.appendChild(html('p', {},
            'Postrouting rules: ' + post.length + ' | Prerouting rules: ' + pre.length));
        return content;
    }, false);
    container.appendChild(natCollapse);
}

function renderConfigRaw(cfg, container) {
    container.appendChild(html('p', { className: 'section-desc mb-3' },
        'Full JSON configuration (read-only)'));
    var pre = html('pre', {}, JSON.stringify(cfg, null, 2));
    container.appendChild(pre);
}

// --- Rules / Logs ---
async function renderLogs() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading firewall rules...'));

    var res = await API.get('firewall/rules');
    var rules = ((res.data || {}).ruleset) || 'No rules loaded';

    view.innerHTML = '';

    var card = html('div', { className: 'card' });
    var cardHeader = html('div', { className: 'card-header' });
    cardHeader.appendChild(html('h3', {}, 'Active Ruleset'));
    var copyBtn = html('button', { className: 'btn btn-sm' }, 'Copy');
    copyBtn.addEventListener('click', function() {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(rules).then(function() {
                notify('Copied to clipboard', 'info');
            });
        }
    });
    cardHeader.appendChild(copyBtn);
    card.appendChild(cardHeader);
    card.appendChild(html('pre', {}, rules));
    view.appendChild(card);
}

/* ============================================================
   Router
   ============================================================ */
function navigate() {
    var hash = location.hash.slice(1) || 'dashboard';
    var route = routes[hash] || routes.dashboard;

    // Update page title
    pageTitle.textContent = route.title;
    document.title = route.title + ' - Firewallo';

    // Update active nav
    document.querySelectorAll('.nav-item').forEach(function(a) {
        a.classList.toggle('active', a.getAttribute('data-view') === hash);
    });

    // Render view with animation
    view.style.animation = 'none';
    /* Force reflow */
    void view.offsetHeight;
    view.style.animation = '';
    route.render();
}

window.addEventListener('hashchange', navigate);
navigate();
