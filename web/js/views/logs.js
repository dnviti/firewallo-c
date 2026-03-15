/* ============================================================
   Firewallo — Logs View
   Live firewall ruleset output from the running kernel
   ============================================================ */

async function renderLogs() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading active rules...'));

    let currentRules = '';

    async function refresh() {
        const res = await API.get('firewall/rules');
        currentRules = (res.data || {}).ruleset || 'No rules loaded';

        view.innerHTML = '';
        view.appendChild(createPageHeader('Active Rules', 'Live firewall ruleset from the running kernel', [
            html('button', { className: 'btn btn-sm',
                onClick: () => copyToClipboard(currentRules) }, 'Copy'),
            html('button', { className: 'btn btn-sm btn-primary',
                onClick: () => refresh() }, 'Refresh Now')
        ]));

        view.appendChild(html('div', { className: 'text-secondary mb-8', style: 'font-size:0.78rem' },
            'Auto-refreshes every 5 seconds'));

        const searchInput = html('input', {
            type: 'text', placeholder: 'Search rules...',
            style: 'width:100%; max-width:400px; margin-bottom:12px',
            onInput: e => {
                const q = e.target.value.toLowerCase();
                const lines = currentRules.split('\n');
                if (q) {
                    const filtered = lines.filter(l => l.toLowerCase().includes(q));
                    preEl.textContent = filtered.length > 0 ? filtered.join('\n') : 'No matching rules';
                } else {
                    preEl.textContent = currentRules;
                }
            }
        });
        view.appendChild(searchInput);

        const preEl = html('pre', {}, currentRules);
        view.appendChild(html('div', { className: 'card' }, preEl));
    }

    await refresh();
    startPolling(refresh, 5000);
}
