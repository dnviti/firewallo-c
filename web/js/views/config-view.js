/* ============================================================
   Firewallo — Config View
   Full configuration viewer (structured + raw JSON)
   ============================================================ */

async function renderConfig() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading configuration...'));

    let currentTab = 'structured';

    async function refresh() {
        const res = await API.get('config');
        const cfg = res.data || {};
        view.innerHTML = '';
        view.appendChild(createPageHeader('Configuration', 'Full firewall configuration \u2014 read-only view'));

        const tabContent = html('div');

        function renderStructured() {
            currentTab = 'structured';
            tabContent.innerHTML = '';
            const sections = [
                { title: 'General', data: { version: cfg.version, language: cfg.language, backend: cfg.backend }, open: true },
                { title: 'Interfaces', data: cfg.interfaces },
                { title: 'DNS Servers', data: cfg.dns_servers },
                { title: 'IP Ranges', data: cfg.ranges },
                { title: 'Sysctl Settings', data: cfg.sysctl },
                { title: 'Filter Chains', data: cfg.filter },
                { title: 'NAT', data: cfg.nat },
                { title: 'Mangle', data: cfg.mangle },
                { title: 'Routes', data: cfg.routes },
                { title: 'DPI', data: cfg.dpi },
                { title: 'Suricata', data: cfg.suricata },
                { title: 'VPN Config', data: cfg.vpn_config }
            ];
            const items = sections
                .filter(s => s.data !== undefined && s.data !== null)
                .map(s => {
                    const jsonStr = JSON.stringify(s.data, null, 2);
                    const content = html('div');
                    content.appendChild(html('div', { className: 'pre-header' },
                        html('span', {}, `${typeof s.data === 'object' ? Object.keys(s.data || {}).length : 1} entries`),
                        html('button', { className: 'btn btn-sm btn-ghost',
                            onClick: () => copyToClipboard(jsonStr) }, 'Copy')));
                    content.appendChild(html('pre', {}, jsonStr));
                    return { title: s.title, content, open: s.open || false };
                });
            tabContent.appendChild(createAccordion(items));
        }

        function renderRawJson() {
            currentTab = 'raw';
            tabContent.innerHTML = '';
            const jsonStr = JSON.stringify(cfg, null, 2);
            const card = html('div', { className: 'card' });
            card.appendChild(html('div', { className: 'pre-header' },
                html('span', {}, 'firewallo.json'),
                html('button', { className: 'btn btn-sm btn-ghost',
                    onClick: () => copyToClipboard(jsonStr) }, 'Copy')));
            card.appendChild(html('pre', {}, jsonStr));
            tabContent.appendChild(card);
        }

        const tabs = createTabs([
            { key: 'structured', label: 'Structured View' },
            { key: 'raw',        label: 'Raw JSON' }
        ], key => key === 'structured' ? renderStructured() : renderRawJson());
        view.appendChild(tabs);
        view.appendChild(tabContent);

        if (currentTab === 'raw') {
            renderRawJson();
            tabs.querySelectorAll('.tab').forEach((b, i) => b.classList.toggle('active', i === 1));
        } else {
            renderStructured();
        }
    }

    await refresh();
    startPolling(refresh, 10000);
}
