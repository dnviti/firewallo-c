/* ============================================================
   Firewallo — NAT View
   Postrouting (MASQUERADE/SNAT) and Prerouting (DNAT) rules
   ============================================================ */

async function renderNat() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading NAT rules...'));

    let currentTab = 'post';

    async function refresh() {
        const cfgRes = await API.get('config');
        const cfg = cfgRes.data || {};
        const nat = cfg.nat || {};

        view.innerHTML = '';
        view.appendChild(createPageHeader('NAT Rules', 'Network Address Translation rules'));

        const tabContent = html('div');

        function renderPostrouting() {
            currentTab = 'post';
            tabContent.innerHTML = '';
            const rules = nat.postrouting || [];
            const addBtn = html('button', { className: 'btn btn-sm btn-primary',
                onClick: () => showNatPostModal(null, -1, refresh) }, '+ Add Rule');
            if (rules.length > 0) {
                const rows = rules.map((r, i) => [
                    r.src || '-', r.oif || '-',
                    createBadge((r.type || 'masquerade').toUpperCase(),
                        r.type === 'snat' ? 'accent' : 'success'),
                    r.to_source || '-', r.comment || '-',
                    html('div', { className: 'btn-group' },
                        html('button', { className: 'btn btn-sm',
                            onClick: () => showNatPostModal(r, i, refresh) }, 'Edit'),
                        html('button', { className: 'btn btn-sm btn-danger',
                            onClick: () => deleteNatPost(i, refresh) }, 'Delete'))
                ]);
                const wrapper = html('div');
                wrapper.appendChild(html('div', { className: 'mb-8', style: 'text-align:right' }, addBtn));
                wrapper.appendChild(createFilterableTable(
                    ['Source', 'Out Interface', 'Type', 'To Source', 'Comment', 'Actions'],
                    rows, { searchPlaceholder: 'Search postrouting...' }));
                tabContent.appendChild(wrapper);
            } else {
                tabContent.appendChild(html('div', { className: 'card' },
                    html('div', { className: 'empty-state' },
                        html('div', { className: 'empty-state-icon' }, '\u2194'),
                        html('div', { className: 'empty-state-text' }, 'No postrouting rules'), addBtn)));
            }
        }

        function renderPrerouting() {
            currentTab = 'pre';
            tabContent.innerHTML = '';
            const rules = nat.prerouting || [];
            const addBtn = html('button', { className: 'btn btn-sm btn-primary',
                onClick: () => showNatPreModal(null, -1, refresh) }, '+ Add Rule');
            if (rules.length > 0) {
                const rows = rules.map((r, i) => [
                    r.iif || '-', createBadge((r.protocol || 'tcp').toUpperCase(), 'accent'),
                    String(r.dport || '-'), r.to_dest_ip || '-',
                    String(r.to_dest_port || '-'), r.comment || '-',
                    html('div', { className: 'btn-group' },
                        html('button', { className: 'btn btn-sm',
                            onClick: () => showNatPreModal(r, i, refresh) }, 'Edit'),
                        html('button', { className: 'btn btn-sm btn-danger',
                            onClick: () => deleteNatPre(i, refresh) }, 'Delete'))
                ]);
                const wrapper = html('div');
                wrapper.appendChild(html('div', { className: 'mb-8', style: 'text-align:right' }, addBtn));
                wrapper.appendChild(createFilterableTable(
                    ['In Interface', 'Protocol', 'Port', 'Dest IP', 'Dest Port', 'Comment', 'Actions'],
                    rows, { searchPlaceholder: 'Search prerouting...' }));
                tabContent.appendChild(wrapper);
            } else {
                tabContent.appendChild(html('div', { className: 'card' },
                    html('div', { className: 'empty-state' },
                        html('div', { className: 'empty-state-icon' }, '\u21B3'),
                        html('div', { className: 'empty-state-text' }, 'No prerouting rules'), addBtn)));
            }
        }

        const tabs = createTabs([
            { key: 'post', label: 'Postrouting', count: (nat.postrouting || []).length },
            { key: 'pre',  label: 'Prerouting',  count: (nat.prerouting || []).length }
        ], key => key === 'post' ? renderPostrouting() : renderPrerouting());
        view.appendChild(tabs);
        view.appendChild(tabContent);

        if (currentTab === 'pre') {
            renderPrerouting();
            tabs.querySelectorAll('.tab').forEach((b, i) => b.classList.toggle('active', i === 1));
        } else {
            renderPostrouting();
        }
    }

    await refresh();
    startPolling(refresh, 5000);
}

function showNatPostModal(existing, index, onDone) {
    showFormModal({
        title: existing ? 'Edit Postrouting Rule' : 'Add Postrouting Rule',
        fields: [
            { key: 'src', label: 'Source', placeholder: 'e.g. 10.0.0.0/24' },
            { key: 'oif', label: 'Out Interface', placeholder: 'e.g. eth0' },
            { key: 'type', label: 'Type', type: 'select', options: [
                { value: 'masquerade', label: 'MASQUERADE' }, { value: 'snat', label: 'SNAT' }]},
            { key: 'to_source', label: 'To Source (SNAT only)', placeholder: 'e.g. 203.0.113.1' },
            { key: 'comment', label: 'Comment', placeholder: 'Optional description' }
        ],
        values: existing ? { src: existing.src || '', oif: existing.oif || '',
            type: existing.type || 'masquerade', to_source: existing.to_source || '',
            comment: existing.comment || '' } : {},
        submitLabel: existing ? 'Update' : 'Add Rule',
        onSubmit: async (data) => {
            const ok = await doubleConfirm(existing ? 'Update Rule' : 'Add Rule',
                `${existing ? 'Update' : 'Add'} this postrouting rule?`,
                existing ? 'Update' : 'Add');
            if (!ok) return;
            const r = await API.mutateConfig(c => {
                if (!c.nat) c.nat = {};
                if (!c.nat.postrouting) c.nat.postrouting = [];
                const rule = { src: data.src, oif: data.oif, type: data.type,
                    dport: null, to_source: data.type === 'snat' ? data.to_source : null,
                    comment: data.comment };
                if (index >= 0) c.nat.postrouting[index] = rule;
                else c.nat.postrouting.push(rule);
            });
            notify(r.ok ? 'Rule saved' : r.message, r.ok ? 'success' : 'error');
            if (r.ok && onDone) onDone();
        }
    });
}

async function deleteNatPost(index, onDone) {
    const ok = await doubleConfirm('Delete Rule', 'Delete this postrouting rule?', 'Delete', 'btn-danger');
    if (!ok) return;
    const r = await API.mutateConfig(c => { if (c.nat && c.nat.postrouting) c.nat.postrouting.splice(index, 1); });
    notify(r.ok ? 'Rule deleted' : r.message, r.ok ? 'success' : 'error');
    if (r.ok && onDone) onDone();
}

function showNatPreModal(existing, index, onDone) {
    showFormModal({
        title: existing ? 'Edit Prerouting Rule' : 'Add Prerouting Rule',
        fields: [
            { key: 'iif', label: 'In Interface', placeholder: 'e.g. eth0' },
            { key: 'protocol', label: 'Protocol', type: 'select', options: [
                { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]},
            { key: 'dport', label: 'Destination Port', type: 'number', min: 1, max: 65535 },
            { key: 'to_dest_ip', label: 'Forward To IP', placeholder: 'e.g. 192.168.1.100' },
            { key: 'to_dest_port', label: 'Forward To Port', type: 'number', min: 1, max: 65535 },
            { key: 'comment', label: 'Comment', placeholder: 'Optional description' }
        ],
        values: existing ? { iif: existing.iif || '', protocol: existing.protocol || 'tcp',
            dport: existing.dport || '', to_dest_ip: existing.to_dest_ip || '',
            to_dest_port: existing.to_dest_port || '', comment: existing.comment || '' } : {},
        submitLabel: existing ? 'Update' : 'Add Rule',
        onSubmit: async (data) => {
            if (!data.dport || !data.to_dest_ip || !data.to_dest_port) {
                notify('Port and destination are required', 'error'); return;
            }
            const ok = await doubleConfirm(existing ? 'Update Rule' : 'Add Rule',
                `${existing ? 'Update' : 'Add'} this prerouting rule?`,
                existing ? 'Update' : 'Add');
            if (!ok) return;
            const r = await API.mutateConfig(c => {
                if (!c.nat) c.nat = {};
                if (!c.nat.prerouting) c.nat.prerouting = [];
                const rule = { iif: data.iif, protocol: data.protocol, dport: data.dport,
                    to_dest_ip: data.to_dest_ip, to_dest_port: data.to_dest_port, comment: data.comment };
                if (index >= 0) c.nat.prerouting[index] = rule;
                else c.nat.prerouting.push(rule);
            });
            notify(r.ok ? 'Rule saved' : r.message, r.ok ? 'success' : 'error');
            if (r.ok && onDone) onDone();
        }
    });
}

async function deleteNatPre(index, onDone) {
    const ok = await doubleConfirm('Delete Rule', 'Delete this prerouting rule?', 'Delete', 'btn-danger');
    if (!ok) return;
    const r = await API.mutateConfig(c => { if (c.nat && c.nat.prerouting) c.nat.prerouting.splice(index, 1); });
    notify(r.ok ? 'Rule deleted' : r.message, r.ok ? 'success' : 'error');
    if (r.ok && onDone) onDone();
}
