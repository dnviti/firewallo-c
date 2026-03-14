const view = document.getElementById('view');

const routes = {
    dashboard: renderDashboard,
    filter: renderFilter,
    nat: renderNat,
    config: renderConfig,
    logs: renderLogs
};

async function renderDashboard() {
    const [status, validate, version] = await Promise.all([
        API.get('firewall/status'),
        API.get('validate'),
        API.get('version')
    ]);

    const s = status.data || {};
    const v = validate.data || {};

    view.innerHTML = '';
    view.appendChild(html('h2', {}, 'Dashboard'));

    const grid = html('div', { className: 'grid grid-3' });
    grid.appendChild(html('div', { className: 'card stat' },
        html('div', { className: 'value' }, s.active ? 'Active' : 'Inactive'),
        html('div', { className: 'label' }, 'Firewall Status')
    ));
    grid.appendChild(html('div', { className: 'card stat' },
        html('div', { className: 'value' }, (s.backend || 'nft').toUpperCase()),
        html('div', { className: 'label' }, 'Backend')
    ));
    grid.appendChild(html('div', { className: 'card stat' },
        html('div', { className: 'value' }, String(v.command_count || 0)),
        html('div', { className: 'label' }, 'Rules')
    ));
    view.appendChild(grid);

    const actions = html('div', { className: 'card' });
    actions.appendChild(html('h3', {}, 'Actions'));
    const btnGroup = html('div', { className: 'btn-group' });
    ['start', 'stop', 'restart', 'reset'].forEach(action => {
        const cls = action === 'reset' ? 'btn btn-danger' : 'btn btn-primary';
        btnGroup.appendChild(html('button', {
            className: cls,
            onclick: async () => {
                const r = await API.post(`firewall/${action}`, {});
                notify(r.error ? r.message : r.data.message, r.error ? 'error' : 'success');
                renderDashboard();
            }
        }, action.charAt(0).toUpperCase() + action.slice(1)));
    });
    actions.appendChild(btnGroup);
    view.appendChild(actions);

    const info = html('div', { className: 'card' });
    info.appendChild(html('h3', {}, 'Version'));
    info.appendChild(html('p', {}, `Firewallo ${(version.data || {}).version || '?'}`));
    info.appendChild(html('p', { className: 'mono' },
        `Valid: ${v.valid ? 'Yes' : 'No'}`));
    view.appendChild(info);
}

async function renderFilter() {
    const res = await API.get('filter');
    const chains = res.data || {};

    view.innerHTML = '';
    view.appendChild(html('h2', {}, 'Filter Chains'));

    const zones = ['fw', 'lan', 'wan', 'dmz', 'vpns'];
    const headerRow = html('div', { className: 'chain-grid' });
    headerRow.appendChild(html('div', { className: 'chain-cell', style: 'visibility:hidden' }));
    ['FW', 'LAN', 'WAN', 'DMZ', 'VPN'].forEach(z =>
        headerRow.appendChild(html('div', { className: 'chain-cell' },
            html('div', { className: 'name' }, z))));

    const grid = html('div');
    grid.appendChild(headerRow);

    zones.forEach(src => {
        const row = html('div', { className: 'chain-grid' });
        row.appendChild(html('div', { className: 'chain-cell' },
            html('div', { className: 'name' }, src.toUpperCase())));
        zones.forEach(dst => {
            const name = `${src}2${dst}`;
            const info = chains[name] || { tcp_count: 0, udp_count: 0 };
            const total = info.tcp_count + info.udp_count + (info.rule_count || 0);
            const cls = total > 0 ? 'chain-cell has-rules' : 'chain-cell';
            row.appendChild(html('div', {
                className: cls,
                onclick: () => renderChainDetail(name)
            },
                html('div', { className: 'name' }, name),
                html('div', { className: 'count' }, `${info.tcp_count}T ${info.udp_count}U`)
            ));
        });
        grid.appendChild(row);
    });
    view.appendChild(grid);
}

async function renderChainDetail(name) {
    const res = await API.get(`filter/${name}`);
    const chain = res.data || {};

    view.innerHTML = '';
    view.appendChild(html('h2', {}, `Chain: ${name}`));
    view.appendChild(html('button', {
        className: 'btn',
        onclick: renderFilter,
        style: 'margin-bottom:16px'
    }, 'Back to Filter Grid'));

    const card = html('div', { className: 'card' });
    card.appendChild(html('h3', {}, 'TCP Ports'));
    if ((chain.tcp_ports || []).length > 0) {
        card.appendChild(html('p', { className: 'mono' }, chain.tcp_ports.join(', ')));
    } else {
        card.appendChild(html('p', { className: 'mono' }, 'None'));
    }

    card.appendChild(html('h3', { style: 'margin-top:16px' }, 'UDP Ports'));
    if ((chain.udp_ports || []).length > 0) {
        card.appendChild(html('p', { className: 'mono' }, chain.udp_ports.join(', ')));
    } else {
        card.appendChild(html('p', { className: 'mono' }, 'None'));
    }
    view.appendChild(card);

    // Add port form
    const addCard = html('div', { className: 'card' });
    addCard.appendChild(html('h3', {}, 'Add Port'));
    const portInput = html('input', { type: 'number', placeholder: 'Port (1-65535)', min: '1', max: '65535' });
    const protoSelect = html('select', {},
        html('option', { value: 'tcp' }, 'TCP'),
        html('option', { value: 'udp' }, 'UDP'));
    const addBtn = html('button', {
        className: 'btn btn-primary',
        onclick: async () => {
            const port = parseInt(portInput.value);
            if (!port || port < 1 || port > 65535) { notify('Invalid port', 'error'); return; }
            const proto = protoSelect.value;
            const r = await API.post(`filter/${name}/${proto}`, { port });
            notify(r.error ? r.message : r.data.message, r.error ? 'error' : 'success');
            renderChainDetail(name);
        }
    }, 'Add');
    const row = html('div', { className: 'btn-group' });
    row.appendChild(portInput);
    row.appendChild(protoSelect);
    row.appendChild(addBtn);
    addCard.appendChild(row);
    view.appendChild(addCard);
}

async function renderNat() {
    const res = await API.get('nat');
    const nat = res.data || {};

    view.innerHTML = '';
    view.appendChild(html('h2', {}, 'NAT Rules'));

    const postCard = html('div', { className: 'card' });
    postCard.appendChild(html('h3', {}, 'Postrouting (MASQUERADE / SNAT)'));
    const postRules = nat.postrouting || [];
    if (postRules.length > 0) {
        postCard.appendChild(createTable(
            ['Source', 'Out Interface', 'Type', 'Comment'],
            postRules.map(r => [r.src, r.oif, r.type, r.comment])
        ));
    } else {
        postCard.appendChild(html('p', {}, 'No postrouting rules configured. NAT masquerade is auto-generated from LAN ranges.'));
    }
    view.appendChild(postCard);

    const preCard = html('div', { className: 'card' });
    preCard.appendChild(html('h3', {}, 'Prerouting (DNAT)'));
    const preRules = nat.prerouting || [];
    if (preRules.length > 0) {
        preCard.appendChild(createTable(
            ['In Interface', 'Protocol', 'Port', 'Dest IP', 'Dest Port', 'Comment'],
            preRules.map(r => [r.iif, r.protocol, r.dport, r.to_dest_ip, r.to_dest_port, r.comment])
        ));
    } else {
        preCard.appendChild(html('p', {}, 'No prerouting rules.'));
    }
    view.appendChild(preCard);
}

async function renderConfig() {
    const res = await API.get('config');
    const cfg = res.data || {};

    view.innerHTML = '';
    view.appendChild(html('h2', {}, 'Configuration'));

    const card = html('div', { className: 'card' });
    const pre = html('pre', {}, JSON.stringify(cfg, null, 2));
    card.appendChild(pre);
    view.appendChild(card);
}

async function renderLogs() {
    view.innerHTML = '';
    view.appendChild(html('h2', {}, 'Firewall Rules'));

    const res = await API.get('firewall/rules');
    const rules = (res.data || {}).ruleset || 'No rules loaded';

    const card = html('div', { className: 'card' });
    card.appendChild(html('pre', {}, rules));
    view.appendChild(card);
}

// Router
function navigate() {
    const hash = location.hash.slice(1) || 'dashboard';
    document.querySelectorAll('#sidebar a').forEach(a => {
        a.classList.toggle('active', a.getAttribute('href') === '#' + hash);
    });
    const fn = routes[hash] || renderDashboard;
    fn();
}

window.addEventListener('hashchange', navigate);
navigate();
