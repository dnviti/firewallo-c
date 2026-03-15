/* ============================================================
   Firewallo — Suricata View
   IDS/IPS settings and blocked protocols management
   ============================================================ */

async function renderSuricata() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading Suricata settings...'));

    async function refresh() {
        const cfgRes = await API.get('config');
        const suricata = (cfgRes.data || {}).suricata || {};
        view.innerHTML = '';
        view.appendChild(createPageHeader('Suricata IDS/IPS', 'Intrusion Detection and Prevention'));

        const enableCard = html('div', { className: 'card' });
        const enableRow = html('div', { className: 'flex items-center justify-between' });
        enableRow.appendChild(html('div', {},
            html('div', { className: 'fw-600' }, 'Suricata Enabled'),
            html('div', { className: 'text-secondary', style: 'font-size:0.82rem' }, 'Enable Suricata IDS/IPS engine')));
        const surToggle = html('label', { className: 'toggle' });
        const surCheck = html('input', { type: 'checkbox' });
        surCheck.checked = !!suricata.enabled;
        surCheck.addEventListener('change', async () => {
            const ok = await doubleConfirm('Toggle Suricata',
                `${surCheck.checked ? 'Enable' : 'Disable'} Suricata?`,
                surCheck.checked ? 'Enable' : 'Disable');
            if (!ok) { surCheck.checked = !surCheck.checked; return; }
            const r = await API.mutateConfig(c => { if (!c.suricata) c.suricata = {}; c.suricata.enabled = surCheck.checked; });
            notify(r.ok ? `Suricata ${surCheck.checked ? 'enabled' : 'disabled'}` : r.message, r.ok ? 'success' : 'error');
            if (!r.ok) surCheck.checked = !surCheck.checked;
        });
        surToggle.appendChild(surCheck);
        surToggle.appendChild(html('span', { className: 'toggle-slider' }));
        enableRow.appendChild(surToggle);
        enableCard.appendChild(enableRow);
        view.appendChild(enableCard);

        const protocols = suricata.blocked_protocols || [];
        view.appendChild(createEditableList({
            title: 'Blocked Protocols',
            items: protocols,
            maxItems: 64,
            placeholder: 'e.g. http, ssh, dns, tls',
            onAdd: async (val) => {
                const ok = await doubleConfirm('Block Protocol',
                    `Block protocol "${val}"?`, 'Block');
                if (!ok) return;
                const r = await API.mutateConfig(c => {
                    if (!c.suricata) c.suricata = {};
                    if (!c.suricata.blocked_protocols) c.suricata.blocked_protocols = [];
                    if (c.suricata.blocked_protocols.includes(val)) throw new Error('Already blocked');
                    c.suricata.blocked_protocols.push(val);
                });
                notify(r.ok ? 'Protocol blocked' : r.message, r.ok ? 'success' : 'error');
                if (r.ok) refresh();
            },
            onRemove: async (val) => {
                const ok = await doubleConfirm('Unblock Protocol',
                    `Unblock protocol "${val}"?`, 'Unblock', 'btn-danger');
                if (!ok) return;
                const r = await API.mutateConfig(c => {
                    const arr = (c.suricata || {}).blocked_protocols || [];
                    const idx = arr.indexOf(val);
                    if (idx >= 0) arr.splice(idx, 1);
                });
                notify(r.ok ? 'Protocol unblocked' : r.message, r.ok ? 'success' : 'error');
                if (r.ok) refresh();
            }
        }));
    }

    await refresh();
    startPolling(refresh, 5000);
}
