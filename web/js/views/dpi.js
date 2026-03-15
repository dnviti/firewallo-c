/* ============================================================
   Firewallo — DPI View
   Deep Packet Inspection rules management
   ============================================================ */

async function renderDpi() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading DPI settings...'));

    async function refresh() {
        const cfgRes = await API.get('config');
        const dpi = (cfgRes.data || {}).dpi || {};
        view.innerHTML = '';
        view.appendChild(createPageHeader('Deep Packet Inspection', 'DPI rules for traffic analysis'));

        const enableCard = html('div', { className: 'card' });
        const enableRow = html('div', { className: 'flex items-center justify-between' });
        enableRow.appendChild(html('div', {},
            html('div', { className: 'fw-600' }, 'DPI Enabled'),
            html('div', { className: 'text-secondary', style: 'font-size:0.82rem' }, 'Enable deep packet inspection')));
        const dpiToggle = html('label', { className: 'toggle' });
        const dpiCheck = html('input', { type: 'checkbox' });
        dpiCheck.checked = !!dpi.enabled;
        dpiCheck.addEventListener('change', async () => {
            const ok = await doubleConfirm('Toggle DPI',
                `${dpiCheck.checked ? 'Enable' : 'Disable'} DPI?`,
                dpiCheck.checked ? 'Enable' : 'Disable');
            if (!ok) { dpiCheck.checked = !dpiCheck.checked; return; }
            const r = await API.mutateConfig(c => { if (!c.dpi) c.dpi = {}; c.dpi.enabled = dpiCheck.checked; });
            notify(r.ok ? `DPI ${dpiCheck.checked ? 'enabled' : 'disabled'}` : r.message, r.ok ? 'success' : 'error');
            if (!r.ok) dpiCheck.checked = !dpiCheck.checked;
        });
        dpiToggle.appendChild(dpiCheck);
        dpiToggle.appendChild(html('span', { className: 'toggle-slider' }));
        enableRow.appendChild(dpiToggle);
        enableCard.appendChild(enableRow);
        view.appendChild(enableCard);

        const rulesCard = html('div', { className: 'card' });
        rulesCard.appendChild(html('div', { className: 'card-header' },
            html('span', { className: 'card-title' }, 'DPI Rules'),
            html('div', { className: 'btn-group' },
                createBadge(String((dpi.rules || []).length), 'accent'),
                html('button', { className: 'btn btn-sm btn-primary',
                    onClick: () => showDpiModal(null, -1, refresh) }, '+ Add Rule'))));
        const rules = dpi.rules || [];
        if (rules.length > 0) {
            const rows = rules.map((r, i) => [
                r.src_addr || 'any', r.dst_addr || 'any',
                createBadge((r.protocol || 'tcp').toUpperCase(), 'accent'),
                formatPort(r.src_port) || 'any', formatPort(r.dst_port) || 'any', r.comment || '-',
                html('div', { className: 'btn-group' },
                    html('button', { className: 'btn btn-sm',
                        onClick: () => showDpiModal(r, i, refresh) }, 'Edit'),
                    html('button', { className: 'btn btn-sm btn-danger',
                        onClick: () => deleteDpi(i, refresh) }, 'Delete'))
            ]);
            rulesCard.appendChild(createFilterableTable(
                ['Source', 'Destination', 'Protocol', 'Src Port', 'Dst Port', 'Comment', 'Actions'], rows));
        } else {
            rulesCard.appendChild(html('div', { className: 'empty-state' },
                html('div', { className: 'empty-state-text' }, 'No DPI rules configured')));
        }
        view.appendChild(rulesCard);
    }

    await refresh();
    startPolling(refresh, 5000);
}

function showDpiModal(existing, index, onDone) {
    showFormModal({
        title: existing ? 'Edit DPI Rule' : 'Add DPI Rule',
        fields: [
            { key: 'src_addr', label: 'Source Address', placeholder: 'e.g. 192.168.1.0/24' },
            { key: 'dst_addr', label: 'Destination Address', placeholder: 'e.g. 10.0.0.0/8' },
            { key: 'protocol', label: 'Protocol', type: 'select', options: [
                { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]},
            { key: 'src_port', label: 'Source Port', placeholder: 'Empty for any' },
            { key: 'dst_port', label: 'Destination Port', placeholder: 'Empty for any' },
            { key: 'comment', label: 'Comment', placeholder: 'Optional description' }
        ],
        values: existing ? { src_addr: existing.src_addr || '', dst_addr: existing.dst_addr || '',
            protocol: existing.protocol || 'tcp', src_port: formatPort(existing.src_port),
            dst_port: formatPort(existing.dst_port), comment: existing.comment || '' } : {},
        submitLabel: existing ? 'Update' : 'Add Rule',
        onSubmit: async (data) => {
            const ok = await doubleConfirm(existing ? 'Update Rule' : 'Add Rule',
                `${existing ? 'Update' : 'Add'} this DPI rule?`, existing ? 'Update' : 'Add');
            if (!ok) return;
            const r = await API.mutateConfig(c => {
                if (!c.dpi) c.dpi = {};
                if (!c.dpi.rules) c.dpi.rules = [];
                const rule = { src_addr: data.src_addr, dst_addr: data.dst_addr, protocol: data.protocol,
                    src_port: parsePortInput(data.src_port), dst_port: parsePortInput(data.dst_port),
                    comment: data.comment };
                if (index >= 0) c.dpi.rules[index] = rule;
                else c.dpi.rules.push(rule);
            });
            notify(r.ok ? 'Rule saved' : r.message, r.ok ? 'success' : 'error');
            if (r.ok && onDone) onDone();
        }
    });
}

async function deleteDpi(index, onDone) {
    const ok = await doubleConfirm('Delete Rule', 'Delete this DPI rule?', 'Delete', 'btn-danger');
    if (!ok) return;
    const r = await API.mutateConfig(c => { if (c.dpi && c.dpi.rules) c.dpi.rules.splice(index, 1); });
    notify(r.ok ? 'Rule deleted' : r.message, r.ok ? 'success' : 'error');
    if (r.ok && onDone) onDone();
}
