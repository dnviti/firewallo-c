/* ============================================================
   Firewallo — Mangle View
   Packet marking and mangling rules (prerouting/postrouting)
   ============================================================ */

async function renderMangle() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading mangle rules...'));
    let currentTab = 'prerouting';

    async function refresh() {
        const cfgRes = await API.get('config');
        const mangle = (cfgRes.data || {}).mangle || {};
        view.innerHTML = '';
        view.appendChild(createPageHeader('Mangle Rules', 'Packet marking and mangling'));
        const tabContent = html('div');

        function renderTab(key) {
            currentTab = key;
            tabContent.innerHTML = '';
            const rules = mangle[key] || [];
            const addBtn = html('button', { className: 'btn btn-sm btn-primary',
                onClick: () => showMangleModal(key, null, -1, refresh) }, '+ Add Rule');
            if (rules.length > 0) {
                const rows = rules.map((r, i) => [
                    r.iif || '-', r.src_addr || 'any', r.dst_addr || 'any',
                    createBadge((r.protocol || 'tcp').toUpperCase(), 'accent'),
                    String(r.dport || 'any'), html('code', {}, r.mark || '-'), r.comment || '-',
                    html('div', { className: 'btn-group' },
                        html('button', { className: 'btn btn-sm',
                            onClick: () => showMangleModal(key, r, i, refresh) }, 'Edit'),
                        html('button', { className: 'btn btn-sm btn-danger',
                            onClick: () => deleteMangle(key, i, refresh) }, 'Delete'))
                ]);
                const wrapper = html('div');
                wrapper.appendChild(html('div', { className: 'mb-8', style: 'text-align:right' }, addBtn));
                wrapper.appendChild(createFilterableTable(
                    ['Interface', 'Source', 'Destination', 'Protocol', 'Port', 'Mark', 'Comment', 'Actions'],
                    rows));
                tabContent.appendChild(wrapper);
            } else {
                tabContent.appendChild(html('div', { className: 'card' },
                    html('div', { className: 'empty-state' },
                        html('div', { className: 'empty-state-text' }, `No ${key} mangle rules`), addBtn)));
            }
        }

        const tabs = createTabs([
            { key: 'prerouting', label: 'Prerouting', count: (mangle.prerouting || []).length },
            { key: 'postrouting', label: 'Postrouting', count: (mangle.postrouting || []).length }
        ], key => renderTab(key));
        view.appendChild(tabs);
        view.appendChild(tabContent);
        renderTab(currentTab);
        const tabBtns = tabs.querySelectorAll('.tab');
        tabBtns.forEach((b, i) => b.classList.toggle('active', i === (currentTab === 'postrouting' ? 1 : 0)));
    }

    await refresh();
    startPolling(refresh, 5000);
}

function showMangleModal(chain, existing, index, onDone) {
    showFormModal({
        title: existing ? 'Edit Mangle Rule' : 'Add Mangle Rule',
        fields: [
            { key: 'iif', label: 'Interface', placeholder: 'e.g. eth0' },
            { key: 'src_addr', label: 'Source Address', placeholder: 'e.g. 192.168.1.0/24' },
            { key: 'dst_addr', label: 'Destination Address', placeholder: 'e.g. 10.0.0.0/8' },
            { key: 'protocol', label: 'Protocol', type: 'select', options: [
                { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]},
            { key: 'dport', label: 'Destination Port', type: 'number', min: 1, max: 65535 },
            { key: 'mark', label: 'Mark Value', placeholder: 'e.g. 0x1' },
            { key: 'comment', label: 'Comment', placeholder: 'Optional description' }
        ],
        values: existing ? { iif: existing.iif || '', src_addr: existing.src_addr || '',
            dst_addr: existing.dst_addr || '', protocol: existing.protocol || 'tcp',
            dport: existing.dport || '', mark: existing.mark || '', comment: existing.comment || '' } : {},
        submitLabel: existing ? 'Update' : 'Add Rule',
        onSubmit: async (data) => {
            const ok = await doubleConfirm(existing ? 'Update Rule' : 'Add Rule',
                `${existing ? 'Update' : 'Add'} this mangle rule?`, existing ? 'Update' : 'Add');
            if (!ok) return;
            const r = await API.mutateConfig(c => {
                if (!c.mangle) c.mangle = {};
                if (!c.mangle[chain]) c.mangle[chain] = [];
                const rule = { iif: data.iif, src_addr: data.src_addr, dst_addr: data.dst_addr,
                    protocol: data.protocol, dport: data.dport || 0, mark: data.mark, comment: data.comment };
                if (index >= 0) c.mangle[chain][index] = rule;
                else c.mangle[chain].push(rule);
            });
            notify(r.ok ? 'Rule saved' : r.message, r.ok ? 'success' : 'error');
            if (r.ok && onDone) onDone();
        }
    });
}

async function deleteMangle(chain, index, onDone) {
    const ok = await doubleConfirm('Delete Rule', 'Delete this mangle rule?', 'Delete', 'btn-danger');
    if (!ok) return;
    const r = await API.mutateConfig(c => { if (c.mangle && c.mangle[chain]) c.mangle[chain].splice(index, 1); });
    notify(r.ok ? 'Rule deleted' : r.message, r.ok ? 'success' : 'error');
    if (r.ok && onDone) onDone();
}
