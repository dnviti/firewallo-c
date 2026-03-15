/* ============================================================
   Firewallo — Filter View
   Filter chain listing, chain detail with TCP/UDP ports, explicit rules
   ============================================================ */

async function renderFilter() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading filter chains...'));

    let currentZone = 'fw';

    async function refresh() {
        const res = await API.get('filter');
        const chains = res.data || {};

        view.innerHTML = '';
        view.appendChild(createPageHeader('Filter Chains',
            'Manage firewall filter rules organized by zone'));

        const zones = [
            { key: 'fw',   label: 'Firewall' },
            { key: 'lan',  label: 'LAN' },
            { key: 'wan',  label: 'WAN' },
            { key: 'dmz',  label: 'DMZ' },
            { key: 'vpns', label: 'VPN' }
        ];
        const destZones = ['fw', 'lan', 'wan', 'dmz', 'vpns'];
        const destLabels = { fw: 'FW', lan: 'LAN', wan: 'WAN', dmz: 'DMZ', vpns: 'VPN' };

        const zoneCounts = zones.map(z => {
            let count = 0;
            destZones.forEach(d => {
                const name = `${z.key}2${d}`;
                const info = chains[name] || {};
                count += (info.tcp_count || 0) + (info.udp_count || 0) + (info.rule_count || 0);
            });
            return count;
        });

        const tabContent = html('div');

        function renderZoneTab(srcKey) {
            currentZone = srcKey;
            tabContent.innerHTML = '';
            const rows = [];
            destZones.forEach(dst => {
                const name = `${srcKey}2${dst}`;
                const info = chains[name] || { tcp_count: 0, udp_count: 0, rule_count: 0 };
                const total = info.tcp_count + info.udp_count + (info.rule_count || 0);
                const direction = html('span', { className: 'chain-arrow' },
                    html('span', { className: 'fw-600' }, srcKey.toUpperCase()),
                    html('span', { className: 'arrow' }, ' \u2192 '),
                    html('span', { className: 'fw-600' }, destLabels[dst] || dst.toUpperCase()));
                const totalBadge = total > 0 ? createBadge(String(total), 'success') : createBadge('0', 'neutral');
                const viewBtn = html('button', { className: 'btn btn-sm',
                    onClick: () => { stopPolling(); renderChainDetail(name); }
                }, 'View / Edit');
                rows.push([name, direction, String(info.tcp_count || 0),
                    String(info.udp_count || 0), String(info.rule_count || 0), totalBadge, viewBtn]);
            });
            tabContent.appendChild(createFilterableTable(
                ['Chain', 'Direction', 'TCP', 'UDP', 'Rules', 'Total', 'Actions'],
                rows, { searchPlaceholder: 'Search chains...' }));
        }

        const tabs = createTabs(zones.map((z, i) => ({
            key: z.key, label: z.label, count: zoneCounts[i]
        })), key => renderZoneTab(key));
        view.appendChild(tabs);
        view.appendChild(tabContent);

        // Re-select the previously active tab
        renderZoneTab(currentZone);
        const tabBtns = tabs.querySelectorAll('.tab');
        const zoneIdx = zones.findIndex(z => z.key === currentZone);
        tabBtns.forEach((b, i) => b.classList.toggle('active', i === zoneIdx));
    }

    await refresh();
    startPolling(refresh, 5000);
}

// ---- Chain Detail — Real-time + double confirm ----
async function renderChainDetail(name) {
    view.innerHTML = '';
    view.appendChild(createLoading(`Loading ${name}...`));

    async function refresh() {
        const res = await API.get(`filter/${name}`);
        const chain = res.data || {};

        view.innerHTML = '';
        view.appendChild(createBreadcrumb([
            { label: 'Filter Chains', href: '#filter', onClick: () => { stopPolling(); renderFilter(); } },
            { label: name }
        ]));

        const parts = name.match(/^(\w+)2(\w+)$/);
        const src = parts ? parts[1].toUpperCase() : '?';
        const dst = parts ? parts[2].toUpperCase() : '?';
        view.appendChild(createPageHeader(`${src} \u2192 ${dst}`, `Chain: ${name}`));

        // TCP Ports
        const tcpCard = html('div', { className: 'card' });
        tcpCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'TCP Ports'),
            createBadge(String((chain.tcp_ports || []).length), 'accent')));
        if ((chain.tcp_ports || []).length > 0) {
            tcpCard.appendChild(createTagList(chain.tcp_ports, async port => {
                const ok = await doubleConfirm('Remove TCP Port',
                    `Remove port ${port} from ${name}?`, 'Remove', 'btn-danger');
                if (!ok) return;
                const r = await API.del(`filter/${name}/tcp/${port}`);
                notify(r.error ? r.message : 'Port removed', r.error ? 'error' : 'success');
                if (!r.error) refresh();
            }));
        } else {
            tcpCard.appendChild(html('div', { className: 'empty-state' },
                html('div', { className: 'empty-state-text' }, 'No TCP ports configured')));
        }
        view.appendChild(tcpCard);

        // UDP Ports
        const udpCard = html('div', { className: 'card' });
        udpCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'UDP Ports'),
            createBadge(String((chain.udp_ports || []).length), 'accent')));
        if ((chain.udp_ports || []).length > 0) {
            udpCard.appendChild(createTagList(chain.udp_ports, async port => {
                const ok = await doubleConfirm('Remove UDP Port',
                    `Remove port ${port} from ${name}?`, 'Remove', 'btn-danger');
                if (!ok) return;
                const r = await API.del(`filter/${name}/udp/${port}`);
                notify(r.error ? r.message : 'Port removed', r.error ? 'error' : 'success');
                if (!r.error) refresh();
            }));
        } else {
            udpCard.appendChild(html('div', { className: 'empty-state' },
                html('div', { className: 'empty-state-text' }, 'No UDP ports configured')));
        }
        view.appendChild(udpCard);

        // Add port form
        const addCard = html('div', { className: 'card' });
        addCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'Add Port')));
        const portInput = html('input', { type: 'number', placeholder: 'Port (1-65535)',
            min: '1', max: '65535', style: 'width:160px' });
        const protoSelect = html('select', {},
            html('option', { value: 'tcp' }, 'TCP'),
            html('option', { value: 'udp' }, 'UDP'));
        const addBtn = html('button', {
            className: 'btn btn-primary',
            onClick: async () => {
                const port = parseInt(portInput.value);
                if (!port || port < 1 || port > 65535) { notify('Invalid port (1-65535)', 'error'); return; }
                const ok = await doubleConfirm('Add Port',
                    `Add ${protoSelect.value.toUpperCase()} port ${port} to ${name}?`, 'Add');
                if (!ok) return;
                const r = await API.post(`filter/${name}/${protoSelect.value}`, { port });
                notify(r.error ? r.message : 'Port added', r.error ? 'error' : 'success');
                if (!r.error) refresh();
            }
        }, 'Add Port');
        portInput.addEventListener('keydown', e => { if (e.key === 'Enter') addBtn.click(); });
        const frow = html('div', { className: 'form-row' });
        frow.appendChild(formField('Port', portInput));
        frow.appendChild(formField('Protocol', protoSelect));
        frow.appendChild(html('div', { className: 'form-group' },
            html('label', { className: 'form-label' }, '\u00A0'), addBtn));
        addCard.appendChild(frow);
        view.appendChild(addCard);

        // Explicit rules
        const rulesCard = html('div', { className: 'card' });
        rulesCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'Explicit Rules'),
            html('div', { className: 'btn-group' },
                createBadge(String((chain.rules || []).length), 'accent'),
                html('button', { className: 'btn btn-sm btn-primary',
                    onClick: () => showFilterRuleModal(name, null, -1, refresh) }, '+ Add Rule')
            )));
        const rules = chain.rules || [];
        if (rules.length > 0) {
            const ruleRows = rules.map((r, i) => [
                r.src_addr || 'any', r.dst_addr || 'any',
                createBadge((r.protocol || 'tcp').toUpperCase(), 'accent'),
                String(r.dst_port || 'any'),
                createBadge(r.action || 'accept',
                    r.action === 'drop' ? 'danger' : r.action === 'reject' ? 'warning' : 'success'),
                r.comment || '-',
                html('div', { className: 'btn-group' },
                    html('button', { className: 'btn btn-sm',
                        onClick: () => showFilterRuleModal(name, r, i, refresh) }, 'Edit'),
                    html('button', { className: 'btn btn-sm btn-danger',
                        onClick: () => deleteFilterRule(name, i, refresh) }, 'Delete'))
            ]);
            rulesCard.appendChild(createFilterableTable(
                ['Source', 'Destination', 'Protocol', 'Dest Port', 'Action', 'Comment', 'Actions'],
                ruleRows, { searchPlaceholder: 'Search rules...' }));
        } else {
            rulesCard.appendChild(html('div', { className: 'empty-state' },
                html('div', { className: 'empty-state-text' }, 'No explicit rules configured'),
                html('div', { className: 'text-muted', style: 'font-size:0.82rem' },
                    'Explicit rules allow fine-grained control beyond simple port opens')));
        }
        view.appendChild(rulesCard);
    }

    await refresh();
    startPolling(refresh, 5000);
}

function showFilterRuleModal(chainName, existing, index, onDone) {
    showFormModal({
        title: existing ? 'Edit Filter Rule' : 'Add Filter Rule',
        fields: [
            { key: 'src_addr', label: 'Source Address', placeholder: 'e.g. 192.168.1.0/24', hint: 'Leave empty for "any"' },
            { key: 'dst_addr', label: 'Destination Address', placeholder: 'e.g. 10.0.0.0/8', hint: 'Leave empty for "any"' },
            { key: 'protocol', label: 'Protocol', type: 'select', options: [
                { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]},
            { key: 'src_port', label: 'Source Port', placeholder: 'e.g. 1024 or 1024:65535', hint: 'Single port, range, or empty for any' },
            { key: 'dst_port', label: 'Destination Port', placeholder: 'e.g. 80 or 80:443', hint: 'Single port, range, or empty for any' },
            { key: 'action', label: 'Action', type: 'select', options: [
                { value: 'accept', label: 'Accept' }, { value: 'drop', label: 'Drop' }, { value: 'reject', label: 'Reject' }]},
            { key: 'comment', label: 'Comment', placeholder: 'Optional description' }
        ],
        values: existing ? {
            src_addr: existing.src_addr || '', dst_addr: existing.dst_addr || '',
            protocol: existing.protocol || 'tcp',
            src_port: formatPort(existing.src_port), dst_port: formatPort(existing.dst_port),
            action: existing.action || 'accept', comment: existing.comment || ''
        } : {},
        submitLabel: existing ? 'Update' : 'Add Rule',
        onSubmit: async (data) => {
            const ok = await doubleConfirm(
                existing ? 'Update Rule' : 'Add Rule',
                `${existing ? 'Update' : 'Add'} this filter rule on chain ${chainName}?`,
                existing ? 'Update' : 'Add');
            if (!ok) return;
            const rule = {
                src_addr: data.src_addr || '', dst_addr: data.dst_addr || '',
                protocol: data.protocol,
                src_port: parsePortInput(data.src_port), dst_port: parsePortInput(data.dst_port),
                action: data.action, comment: data.comment || ''
            };
            const r = await API.mutateConfig(c => {
                const chain = (c.filter || {})[chainName];
                if (!chain) throw new Error('Chain not found');
                if (!chain.rules) chain.rules = [];
                if (index >= 0) chain.rules[index] = rule;
                else chain.rules.push(rule);
            });
            notify(r.ok ? (existing ? 'Rule updated' : 'Rule added') : r.message,
                   r.ok ? 'success' : 'error');
            if (r.ok && onDone) onDone();
        }
    });
}

async function deleteFilterRule(chainName, index, onDone) {
    const ok = await doubleConfirm('Delete Rule',
        'Are you sure you want to delete this filter rule?', 'Delete', 'btn-danger');
    if (!ok) return;
    const r = await API.mutateConfig(c => {
        const chain = (c.filter || {})[chainName];
        if (chain && chain.rules) chain.rules.splice(index, 1);
    });
    notify(r.ok ? 'Rule deleted' : r.message, r.ok ? 'success' : 'error');
    if (r.ok && onDone) onDone();
}
