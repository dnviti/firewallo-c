/* ============================================================
   Firewallo — VPN View
   Tunnel management, peer management, multi-step creation wizard
   ============================================================ */

/* ---------- Tunnel Management (#vpn) ---------- */

async function renderVpn() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading VPN tunnels...'));

    async function refresh() {
        let tunnels = [];
        try {
            const res = await API.get('vpn/tunnels');
            tunnels = Array.isArray(res.data) ? res.data : [];
        } catch (e) { tunnels = []; }

        view.innerHTML = '';
        view.appendChild(createPageHeader('VPN Tunnels',
            'Manage WireGuard, OpenVPN and IPSec tunnels',
            [html('button', { className: 'btn btn-primary',
                onClick: () => showVpnWizard(refresh) }, '+ Create Tunnel')]
        ));

        if (tunnels.length === 0) {
            view.appendChild(html('div', { className: 'card' },
                html('div', { className: 'empty-state' },
                    html('div', { className: 'empty-state-icon' }, '\u{1F510}'),
                    html('div', { className: 'empty-state-text' }, 'No VPN tunnels configured'),
                    html('button', { className: 'btn btn-primary',
                        onClick: () => showVpnWizard(refresh) }, '+ Create Tunnel'))));
            return;
        }

        const grid = html('div', { className: 'grid grid-2' });
        tunnels.forEach(t => {
            const protoBadge = t.protocol === 'wireguard' ? 'accent' : t.protocol === 'openvpn' ? 'success' : 'warning';
            const protoLabel = t.protocol === 'wireguard' ? 'WG' : t.protocol === 'openvpn' ? 'OVPN' : 'IPSec';
            const isUp = t.active || t.status === 'up';

            const card = html('div', { className: 'card' });
            card.appendChild(html('div', { className: 'card-header' },
                html('span', { className: 'card-title' }, t.name || 'Unnamed'),
                html('div', { className: 'btn-group' },
                    createBadge(protoLabel, protoBadge),
                    t.mode ? createBadge(t.mode, 'neutral') : null,
                    createBadge(isUp ? 'UP' : 'DOWN', isUp ? 'success' : 'danger'))));

            const details = html('div', { className: 'grid grid-2', style: { gap: '0.5rem', padding: '0 0 12px' } });
            const di = (l, v) => html('div', {},
                html('div', { className: 'text-secondary', style: { fontSize: '0.78rem' } }, l),
                html('div', { className: 'fw-600' }, v || '-'));
            details.appendChild(di('Endpoint', t.endpoint || (t.listen_port ? ':' + t.listen_port : '-')));
            details.appendChild(di('Local Network', t.local_network));
            details.appendChild(di('Interface', t.interface || t.name));
            if (t.remote_network) details.appendChild(di('Remote Network', t.remote_network));
            card.appendChild(details);

            const actions = html('div', { className: 'btn-group' });
            actions.appendChild(html('button', {
                className: isUp ? 'btn btn-sm btn-warning' : 'btn btn-sm btn-success',
                onClick: async () => {
                    const label = isUp ? 'Stop' : 'Start';
                    const ok = await doubleConfirm(label + ' Tunnel', label + ' "' + t.name + '"?', label, isUp ? 'btn-warning' : 'btn-success');
                    if (!ok) return;
                    const r = await API.post('vpn/tunnels/' + encodeURIComponent(t.name) + '/' + (isUp ? 'stop' : 'start'), {});
                    notify(r.error ? r.message : 'Tunnel ' + (isUp ? 'stopped' : 'started'), r.error ? 'error' : 'success');
                    refresh();
                }
            }, isUp ? 'Stop' : 'Start'));
            actions.appendChild(html('button', { className: 'btn btn-sm',
                onClick: () => showEditTunnelModal(t, refresh) }, 'Edit'));
            actions.appendChild(html('button', { className: 'btn btn-sm btn-danger',
                onClick: async () => {
                    const ok = await doubleConfirm('Delete Tunnel', 'Delete "' + t.name + '"?', 'Delete', 'btn-danger');
                    if (!ok) return;
                    const r = await API.del('vpn/tunnels/' + encodeURIComponent(t.name));
                    notify(r.error ? r.message : 'Tunnel deleted', r.error ? 'error' : 'success');
                    refresh();
                }
            }, 'Delete'));
            card.appendChild(actions);
            grid.appendChild(card);
        });
        view.appendChild(grid);
    }

    await refresh();
    startPolling(refresh, 5000);
}

/* ---------- Edit Tunnel Modal ---------- */

function showEditTunnelModal(tunnel, onDone) {
    showFormModal({
        title: 'Edit Tunnel: ' + tunnel.name,
        fields: [
            { key: 'name', label: 'Tunnel Name', placeholder: 'e.g. wg0' },
            { key: 'listen_port', label: 'Listen Port', type: 'number', min: 1, max: 65535 },
            { key: 'local_network', label: 'Local Network CIDR', placeholder: 'e.g. 10.0.0.1/24' },
            { key: 'endpoint', label: 'Remote Endpoint', placeholder: 'e.g. vpn.example.com:51820' },
            { key: 'remote_network', label: 'Remote Network', placeholder: 'e.g. 10.0.1.0/24' },
            { key: 'interface', label: 'Interface', placeholder: 'e.g. wg0' }
        ],
        values: { name: tunnel.name || '', listen_port: tunnel.listen_port || '',
            local_network: tunnel.local_network || '', endpoint: tunnel.endpoint || '',
            remote_network: tunnel.remote_network || '', interface: tunnel.interface || '' },
        submitLabel: 'Update',
        onSubmit: async (data) => {
            const ok = await doubleConfirm('Update Tunnel', 'Update "' + tunnel.name + '"?', 'Update');
            if (!ok) return;
            const r = await API.put('vpn/tunnels/' + encodeURIComponent(tunnel.name), data);
            notify(r.error ? r.message : 'Tunnel updated', r.error ? 'error' : 'success');
            if (!r.error && onDone) onDone();
        }
    });
}

/* ---------- Create Tunnel Wizard ---------- */

function showVpnWizard(onDone) {
    let step = 1;
    const wiz = {
        protocol: '', mode: '', name: '', listen_port: '',
        local_network: '', endpoint: '', remote_network: '',
        private_key: '', public_key: '',
        ca_path: '', cert_path: '', key_path: '', dh_path: '', cipher: 'AES-256-GCM',
        auth_method: 'psk', psk: '', local_id: '', remote_id: ''
    };

    const overlay = html('div', { className: 'modal-overlay' });
    const modal = html('div', { className: 'modal modal-wide' });
    const headerEl = html('div', { className: 'modal-header' },
        html('div', { className: 'modal-title' }, ''),
        html('button', { className: 'modal-close', onClick: close }, '\u00D7'));
    const bodyEl = html('div', { className: 'modal-body' });
    const footerEl = html('div', { className: 'modal-footer' });
    modal.appendChild(headerEl);
    modal.appendChild(bodyEl);
    modal.appendChild(footerEl);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('visible'));
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });

    function close() {
        overlay.classList.remove('visible');
        setTimeout(() => overlay.remove(), 200);
    }

    // --- Selectable option card helper ---
    function optionCard(key, currentValue, label, badgeText, badgeType, description, learnContent, onSelect) {
        const selected = currentValue === key;
        const card = html('div', {
            style: 'border:2px solid ' + (selected ? 'var(--accent)' : 'var(--border)') +
                   ';border-radius:var(--radius-lg);cursor:pointer;transition:all 0.2s;' +
                   'background:' + (selected ? 'var(--accent-bg)' : 'var(--bg-card)'),
            onClick: () => onSelect(key)
        });

        const header = html('div', { style: 'padding:16px 16px 0' },
            html('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:8px' },
                selected ? html('span', { style: 'color:var(--accent);font-size:1.2rem' }, '\u25C9') :
                           html('span', { style: 'color:var(--text-muted);font-size:1.2rem' }, '\u25CB'),
                html('strong', { style: 'font-size:1.05rem' }, label),
                badgeText ? createBadge(badgeText, badgeType) : null),
            html('div', { className: 'text-secondary', style: 'font-size:0.87rem;padding-bottom:12px' }, description));
        card.appendChild(header);

        if (learnContent) {
            card.appendChild(createAccordion([{
                title: 'Learn more',
                content: html('div', { className: 'text-secondary', style: 'font-size:0.85rem;line-height:1.6' }, learnContent)
            }]));
        }
        return card;
    }

    function renderStep() {
        bodyEl.innerHTML = '';
        footerEl.innerHTML = '';
        headerEl.querySelector('.modal-title').textContent = 'Create VPN Tunnel \u2014 Step ' + step + ' of 5';

        // Progress bar
        const progress = html('div', { style: 'display:flex;gap:4px;margin-bottom:16px' });
        for (let i = 1; i <= 5; i++) {
            const color = i < step ? 'var(--success)' : i === step ? 'var(--accent)' : 'var(--border)';
            progress.appendChild(html('div', { style: 'flex:1;height:4px;border-radius:2px;background:' + color }));
        }
        bodyEl.appendChild(progress);

        if (step === 1) renderStep1();
        else if (step === 2) renderStep2();
        else if (step === 3) renderStep3();
        else if (step === 4) renderStep4();
        else renderStep5();

        // Footer
        footerEl.appendChild(html('button', { className: 'btn',
            onClick: () => { if (step === 1) close(); else { step--; renderStep(); } }
        }, step === 1 ? 'Cancel' : 'Back'));

        if (step < 5) {
            footerEl.appendChild(html('button', { className: 'btn btn-primary',
                onClick: () => {
                    if (step === 1 && !wiz.protocol) { notify('Select a protocol', 'error'); return; }
                    if (step === 2 && !wiz.mode) { notify('Select a mode', 'error'); return; }
                    if (step === 3 && !wiz.name.trim()) { notify('Tunnel name is required', 'error'); return; }
                    if (step === 3 && !wiz.local_network.trim()) { notify('Local network is required', 'error'); return; }
                    step++;
                    renderStep();
                }
            }, 'Next'));
        }
    }

    // ---- Step 1: Protocol ----
    function renderStep1() {
        bodyEl.appendChild(html('h3', { style: 'margin:0 0 12px' }, 'Choose a VPN Protocol'));

        const container = html('div', { className: 'grid grid-3', style: 'gap:12px' });
        function selectProto(key) {
            wiz.protocol = key;
            if (key === 'wireguard') wiz.listen_port = 51820;
            else if (key === 'openvpn') wiz.listen_port = 1194;
            else wiz.listen_port = 500;
            renderStep();
        }

        container.appendChild(optionCard('wireguard', wiz.protocol, 'WireGuard', 'WG', 'accent',
            'Modern, fast, simple. Built into Linux kernel. Uses state-of-the-art cryptography. Best for most use cases.',
            'WireGuard uses the Noise protocol framework with Curve25519 for key exchange, ChaCha20 for encryption, Poly1305 for authentication, and BLAKE2s for hashing. It runs as a kernel module creating a virtual network interface (e.g. wg0). Configuration is minimal: just a private key, peer public keys, and allowed IP ranges.',
            selectProto));

        container.appendChild(optionCard('openvpn', wiz.protocol, 'OpenVPN', 'OVPN', 'success',
            'Battle-tested, certificate-based. Works through restrictive firewalls (TCP/443). Best for compatibility.',
            'OpenVPN uses the OpenSSL library and can operate over UDP (faster, default port 1194) or TCP (can traverse HTTP proxies on port 443). Authentication is certificate-based using a PKI with a Certificate Authority, server certificate, client certificates, and Diffie-Hellman parameters.',
            selectProto));

        container.appendChild(optionCard('ipsec', wiz.protocol, 'IPSec', 'IPSec', 'warning',
            'Industry standard for site-to-site. Used by enterprise equipment (Cisco, Fortinet). Best for connecting office networks.',
            'IPSec operates at the network layer using IKE (Internet Key Exchange) for negotiating security associations, and ESP (Encapsulating Security Payload) for encrypting traffic. Common implementations include StrongSwan and Libreswan. IPSec can run in tunnel mode (entire packet encrypted) or transport mode.',
            selectProto));

        bodyEl.appendChild(container);
    }

    // ---- Step 2: Mode ----
    function renderStep2() {
        bodyEl.appendChild(html('h3', { style: 'margin:0 0 12px' }, 'Choose Tunnel Mode'));

        function selectMode(key) { wiz.mode = key; renderStep(); }

        const modes = [
            { key: 'server', label: 'Server', badge: 'Server',
              diagram: 'Remote Clients \u2192 [ Internet ] \u2192 [ Your Firewall / VPN Server ] \u2192 [ Local Network ]',
              learn: 'Your firewall acts as the VPN server, listening for incoming connections from remote clients (laptops, phones). Clients connect over the internet and gain access to your local network. You need to open the listen port in your firewall and configure port forwarding if behind NAT.' },
            { key: 'client', label: 'Client', badge: 'Client',
              diagram: '[ Local Network ] \u2192 [ Your Firewall / VPN Client ] \u2192 [ Internet ] \u2192 [ Remote VPN Server ]',
              learn: 'Your firewall connects as a client to a remote VPN server. All traffic from your local network (or selected routes) is sent through the encrypted tunnel. Useful for connecting a branch office to headquarters. The firewall initiates the connection, so no inbound ports need to be open.' },
            { key: 'site2site', label: 'Site-to-Site', badge: 'S2S',
              diagram: '[ Network A ] \u2192 [ Firewall A ] \u2550\u2550\u2550 encrypted tunnel \u2550\u2550\u2550 [ Firewall B ] \u2192 [ Network B ]',
              learn: 'Two firewalls connect to each other, creating a permanent encrypted link between two networks. Devices on Network A can reach devices on Network B transparently. Both sides need to know each other\'s public IP or dynamic DNS.' }
        ];

        modes.forEach(m => {
            const selected = wiz.mode === m.key;
            const card = html('div', {
                style: 'border:2px solid ' + (selected ? 'var(--accent)' : 'var(--border)') +
                       ';border-radius:var(--radius-lg);cursor:pointer;transition:all 0.2s;margin-bottom:10px;' +
                       'background:' + (selected ? 'var(--accent-bg)' : 'var(--bg-card)'),
                onClick: () => selectMode(m.key)
            });

            card.appendChild(html('div', { style: 'padding:14px 16px 0' },
                html('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:10px' },
                    selected ? html('span', { style: 'color:var(--accent);font-size:1.2rem' }, '\u25C9') :
                               html('span', { style: 'color:var(--text-muted);font-size:1.2rem' }, '\u25CB'),
                    html('strong', { style: 'font-size:1.05rem' }, m.label),
                    createBadge(m.badge, 'neutral')),
                html('div', {
                    style: 'background:var(--bg);border-radius:6px;padding:10px 14px;font-family:var(--mono);font-size:0.82rem;text-align:center;color:var(--accent);overflow-x:auto;white-space:nowrap;margin-bottom:12px'
                }, m.diagram)));

            card.appendChild(createAccordion([{
                title: 'How it works',
                content: html('div', { className: 'text-secondary', style: 'font-size:0.85rem;line-height:1.6' }, m.learn)
            }]));

            bodyEl.appendChild(card);
        });
    }

    // ---- Step 3: Network Config ----
    function renderStep3() {
        bodyEl.appendChild(html('h3', { style: 'margin:0 0 12px' }, 'Network Configuration'));

        function field(label, value, placeholder, hint, onChange) {
            const input = html('input', { type: 'text', style: 'width:100%', placeholder, value: value || '' });
            input.addEventListener('input', () => onChange(input.value));
            return formField(label, input, hint);
        }

        function numField(label, value, placeholder, hint, onChange) {
            const input = html('input', { type: 'number', style: 'width:100%', placeholder,
                min: '1', max: '65535', value: value ? String(value) : '' });
            input.addEventListener('input', () => onChange(input.value ? Number(input.value) : ''));
            return formField(label, input, hint);
        }

        bodyEl.appendChild(field('Tunnel Name *', wiz.name, 'e.g. wg0-office',
            'A unique name for this tunnel. Use lowercase letters, numbers and hyphens.',
            v => wiz.name = v));

        bodyEl.appendChild(numField('Listen Port', wiz.listen_port,
            wiz.protocol === 'wireguard' ? '51820' : wiz.protocol === 'openvpn' ? '1194' : '500',
            'The port this tunnel listens on. Default: ' + (wiz.protocol === 'wireguard' ? '51820' : wiz.protocol === 'openvpn' ? '1194' : '500'),
            v => wiz.listen_port = v));

        bodyEl.appendChild(field('Local Network CIDR *', wiz.local_network, 'e.g. 10.0.0.1/24',
            'The IP address and subnet for the tunnel interface. Example: 10.0.0.1/24 assigns 10.0.0.1 to this side.',
            v => wiz.local_network = v));

        if (wiz.mode === 'client' || wiz.mode === 'site2site') {
            bodyEl.appendChild(field('Remote Endpoint', wiz.endpoint, 'e.g. vpn.example.com:51820',
                'The public IP or hostname:port of the remote VPN peer.',
                v => wiz.endpoint = v));
        }

        if (wiz.mode === 'site2site') {
            bodyEl.appendChild(field('Remote Network', wiz.remote_network, 'e.g. 192.168.1.0/24',
                'The subnet on the remote side that should be reachable through the tunnel.',
                v => wiz.remote_network = v));
        }
    }

    // ---- Step 4: Security ----
    function renderStep4() {
        bodyEl.appendChild(html('h3', { style: 'margin:0 0 12px' }, 'Security Configuration'));

        if (wiz.protocol === 'wireguard') renderStep4WG();
        else if (wiz.protocol === 'openvpn') renderStep4OVPN();
        else renderStep4IPSec();
    }

    function renderStep4WG() {
        const infoCard = html('div', { style: 'background:var(--bg-hover);border-radius:var(--radius);padding:14px;margin-bottom:16px' },
            html('div', { style: 'font-size:0.9rem;margin-bottom:10px;line-height:1.5' },
                'WireGuard uses Curve25519 key pairs. Click below to generate a new keypair. The private key stays on the server and is never transmitted.'),
            html('button', { className: 'btn btn-primary',
                onClick: async () => {
                    try {
                        const r = await API.post('vpn/generate-keys', {});
                        if (r.data) {
                            wiz.private_key = r.data.private_key || '';
                            wiz.public_key = r.data.public_key || '';
                            renderStep();
                            notify('Keys generated', 'success');
                        } else { notify(r.message || 'Failed', 'error'); }
                    } catch (e) { notify('Failed: ' + e.message, 'error'); }
                }
            }, 'Generate Keys'));
        bodyEl.appendChild(infoCard);

        if (wiz.public_key) {
            bodyEl.appendChild(html('div', { style: 'background:var(--bg-hover);border-radius:var(--radius);padding:14px;margin-bottom:12px' },
                html('div', { className: 'text-secondary', style: 'font-size:0.78rem;margin-bottom:4px' }, 'Public Key'),
                html('div', { className: 'mono', style: 'word-break:break-all' }, wiz.public_key),
                html('div', { className: 'text-secondary', style: 'font-size:0.78rem;margin-top:8px' },
                    'Share this key with peers. Private key stored securely on server.')));
        }
        if (wiz.private_key) {
            bodyEl.appendChild(html('div', { style: 'color:var(--success);font-size:0.85rem' },
                '\u2713 Private key generated and stored.'));
        }
    }

    function renderStep4OVPN() {
        function pathField(label, value, placeholder, hint, onChange) {
            const input = html('input', { type: 'text', style: 'width:100%', placeholder, value: value || '' });
            input.addEventListener('input', () => onChange(input.value));
            return formField(label, input, hint);
        }
        bodyEl.appendChild(pathField('CA Certificate Path', wiz.ca_path, '/etc/openvpn/ca.crt',
            'Path to the Certificate Authority file.', v => wiz.ca_path = v));
        bodyEl.appendChild(pathField('Server Certificate Path', wiz.cert_path, '/etc/openvpn/server.crt',
            'Path to the server\'s TLS certificate.', v => wiz.cert_path = v));
        bodyEl.appendChild(pathField('Server Key Path', wiz.key_path, '/etc/openvpn/server.key',
            'Path to the server\'s private key.', v => wiz.key_path = v));
        bodyEl.appendChild(pathField('DH Parameters Path', wiz.dh_path, '/etc/openvpn/dh2048.pem',
            'Generate with: openssl dhparam -out dh2048.pem 2048', v => wiz.dh_path = v));

        const cipherSelect = formSelect([
            { value: 'AES-256-GCM', label: 'AES-256-GCM (recommended)' },
            { value: 'AES-128-GCM', label: 'AES-128-GCM' },
            { value: 'AES-256-CBC', label: 'AES-256-CBC (legacy)' },
            { value: 'CHACHA20-POLY1305', label: 'ChaCha20-Poly1305' }
        ], { style: 'width:100%' });
        cipherSelect.value = wiz.cipher;
        cipherSelect.addEventListener('change', () => wiz.cipher = cipherSelect.value);
        bodyEl.appendChild(formField('Cipher', cipherSelect, 'Encryption algorithm for the data channel.'));
    }

    function renderStep4IPSec() {
        const authSelect = formSelect([
            { value: 'psk', label: 'Pre-Shared Key (PSK)' },
            { value: 'certificate', label: 'Certificate' }
        ], { style: 'width:100%' });
        authSelect.value = wiz.auth_method;
        authSelect.addEventListener('change', () => { wiz.auth_method = authSelect.value; renderStep(); });
        bodyEl.appendChild(formField('Authentication Method', authSelect,
            'PSK is simpler. Certificates scale better for larger deployments.'));

        if (wiz.auth_method === 'psk') {
            const pskInput = html('input', { type: 'password', style: 'width:100%', placeholder: 'Enter pre-shared key', value: wiz.psk || '' });
            pskInput.addEventListener('input', () => wiz.psk = pskInput.value);
            bodyEl.appendChild(formField('Pre-Shared Key', pskInput, 'A secret shared between both sides. Use at least 32 random characters.'));
        }

        const lidInput = html('input', { type: 'text', style: 'width:100%', placeholder: 'e.g. @firewall-a', value: wiz.local_id || '' });
        lidInput.addEventListener('input', () => wiz.local_id = lidInput.value);
        bodyEl.appendChild(formField('Local ID', lidInput, 'Identity sent during IKE negotiation. Usually public IP or @FQDN.'));

        const ridInput = html('input', { type: 'text', style: 'width:100%', placeholder: 'e.g. @firewall-b', value: wiz.remote_id || '' });
        ridInput.addEventListener('input', () => wiz.remote_id = ridInput.value);
        bodyEl.appendChild(formField('Remote ID', ridInput, 'Expected identity of the remote peer.'));
    }

    // ---- Step 5: Review & Create ----
    function renderStep5() {
        bodyEl.appendChild(html('h3', { style: 'margin:0 0 12px' }, 'Review Configuration'));

        const protoLabel = wiz.protocol === 'wireguard' ? 'WireGuard' : wiz.protocol === 'openvpn' ? 'OpenVPN' : 'IPSec';
        const protoBadge = wiz.protocol === 'wireguard' ? 'accent' : wiz.protocol === 'openvpn' ? 'success' : 'warning';

        const summary = html('div', { style: 'border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px;margin-bottom:16px' });
        const grid = html('div', { className: 'grid grid-2', style: 'gap:10px' });

        const si = (l, v) => html('div', {},
            html('div', { className: 'text-secondary', style: 'font-size:0.78rem' }, l),
            html('div', { className: 'fw-600' }, v || '-'));

        grid.appendChild(html('div', {},
            html('div', { className: 'text-secondary', style: 'font-size:0.78rem' }, 'Protocol'),
            html('div', { style: 'display:flex;align-items:center;gap:6px' },
                html('span', { className: 'fw-600' }, protoLabel), createBadge(protoLabel, protoBadge))));
        grid.appendChild(si('Mode', wiz.mode));
        grid.appendChild(si('Tunnel Name', wiz.name));
        grid.appendChild(si('Listen Port', wiz.listen_port ? String(wiz.listen_port) : 'Default'));
        grid.appendChild(si('Local Network', wiz.local_network));
        if (wiz.endpoint) grid.appendChild(si('Remote Endpoint', wiz.endpoint));
        if (wiz.remote_network) grid.appendChild(si('Remote Network', wiz.remote_network));
        if (wiz.protocol === 'wireguard' && wiz.public_key)
            grid.appendChild(si('Public Key', wiz.public_key.substring(0, 24) + '...'));
        if (wiz.protocol === 'openvpn') grid.appendChild(si('Cipher', wiz.cipher));
        if (wiz.protocol === 'ipsec') {
            grid.appendChild(si('Auth', wiz.auth_method === 'psk' ? 'Pre-Shared Key' : 'Certificate'));
            if (wiz.local_id) grid.appendChild(si('Local ID', wiz.local_id));
        }
        summary.appendChild(grid);
        bodyEl.appendChild(summary);

        const createBtn = html('button', {
            className: 'btn btn-primary', style: 'width:100%',
            onClick: async () => {
                createBtn.disabled = true;
                createBtn.textContent = 'Creating...';
                const payload = {
                    protocol: wiz.protocol, mode: wiz.mode, name: wiz.name,
                    listen_port: wiz.listen_port ? Number(wiz.listen_port) : 0,
                    local_network: wiz.local_network, endpoint: wiz.endpoint,
                    remote_network: wiz.remote_network
                };
                if (wiz.protocol === 'wireguard') {
                    payload.private_key = wiz.private_key;
                    payload.public_key = wiz.public_key;
                } else if (wiz.protocol === 'openvpn') {
                    payload.ca_path = wiz.ca_path; payload.cert_path = wiz.cert_path;
                    payload.key_path = wiz.key_path; payload.dh_path = wiz.dh_path;
                    payload.cipher = wiz.cipher;
                } else {
                    payload.auth_method = wiz.auth_method; payload.psk = wiz.psk;
                    payload.local_id = wiz.local_id; payload.remote_id = wiz.remote_id;
                }
                try {
                    const r = await API.post('vpn/tunnels', payload);
                    if (r.error) {
                        notify(r.message || 'Failed', 'error');
                        createBtn.disabled = false; createBtn.textContent = 'Create Tunnel'; return;
                    }
                    notify('Tunnel "' + wiz.name + '" created', 'success');
                    close();
                    const startNow = await confirm('Start Tunnel?',
                        'Would you like to start "' + wiz.name + '" now?', 'Start Now', 'btn-success');
                    if (startNow) {
                        const sr = await API.post('vpn/tunnels/' + encodeURIComponent(wiz.name) + '/start', {});
                        notify(sr.error ? sr.message : 'Tunnel started', sr.error ? 'error' : 'success');
                    }
                    if (onDone) onDone();
                } catch (e) {
                    notify('Error: ' + e.message, 'error');
                    createBtn.disabled = false; createBtn.textContent = 'Create Tunnel';
                }
            }
        }, 'Create Tunnel');
        bodyEl.appendChild(createBtn);
    }

    renderStep();
}

/* ---------- Peer Management (#vpn-peers) ---------- */

async function renderVpnPeers() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading VPN peers...'));

    async function refresh() {
        let peersData = [], tunnelsList = [];
        try {
            const [pRes, tRes] = await Promise.all([API.get('vpn/peers'), API.get('vpn/tunnels')]);
            peersData = Array.isArray(pRes.data) ? pRes.data : [];
            tunnelsList = Array.isArray(tRes.data) ? tRes.data : [];
        } catch (e) { /* defaults */ }

        view.innerHTML = '';
        view.appendChild(createPageHeader('VPN Peers',
            'Manage remote devices that connect to your VPN tunnels',
            [html('button', { className: 'btn btn-primary',
                onClick: () => showPeerModal(null, tunnelsList, refresh) }, '+ Add Peer')]));

        view.appendChild(html('div', {
            style: 'border-left:3px solid var(--accent);padding:12px 16px;margin-bottom:16px;font-size:0.9rem;line-height:1.5;background:var(--bg-card);border-radius:0 var(--radius) var(--radius) 0'
        }, 'Peers are remote devices that connect to your WireGuard VPN tunnels. Each peer needs a unique keypair and allowed IP range. Use the "Config" button to download a ready-to-use client configuration.'));

        if (peersData.length === 0) {
            view.appendChild(html('div', { className: 'card' },
                html('div', { className: 'empty-state' },
                    html('div', { className: 'empty-state-icon' }, '\u{1F465}'),
                    html('div', { className: 'empty-state-text' }, 'No peers configured'),
                    html('button', { className: 'btn btn-primary',
                        onClick: () => showPeerModal(null, tunnelsList, refresh) }, '+ Add Peer'))));
            return;
        }

        const rows = peersData.map(p => [
            p.name || '-', p.tunnel || '-',
            html('span', { className: 'mono', style: 'font-size:0.82rem', title: p.public_key || '' },
                p.public_key ? p.public_key.substring(0, 16) + '...' : '-'),
            p.allowed_ips || '-', p.endpoint || '-',
            p.keepalive ? p.keepalive + 's' : '-',
            html('div', { className: 'btn-group' },
                html('button', { className: 'btn btn-sm btn-primary',
                    onClick: () => showPeerConfig(p) }, 'Config'),
                html('button', { className: 'btn btn-sm',
                    onClick: () => showPeerModal(p, tunnelsList, refresh) }, 'Edit'),
                html('button', { className: 'btn btn-sm btn-danger',
                    onClick: async () => {
                        const ok = await doubleConfirm('Delete Peer', 'Delete "' + p.name + '"?', 'Delete', 'btn-danger');
                        if (!ok) return;
                        const r = await API.del('vpn/peers/' + encodeURIComponent(p.name));
                        notify(r.error ? r.message : 'Peer deleted', r.error ? 'error' : 'success');
                        refresh();
                    }
                }, 'Delete'))
        ]);

        view.appendChild(createFilterableTable(
            ['Name', 'Tunnel', 'Public Key', 'Allowed IPs', 'Endpoint', 'Keepalive', 'Actions'],
            rows, { searchPlaceholder: 'Search peers...' }));
    }

    await refresh();
    startPolling(refresh, 5000);
}

/* ---------- Add/Edit Peer Modal ---------- */

function showPeerModal(existing, tunnels, onDone) {
    const tunnelOpts = (Array.isArray(tunnels) ? tunnels : []).map(t => ({
        value: t.name, label: t.name + ' (' + (t.protocol || '') + ')'
    }));
    if (tunnelOpts.length === 0) tunnelOpts.push({ value: '', label: 'No tunnels available' });

    showFormModal({
        title: existing ? 'Edit Peer: ' + existing.name : 'Add Peer',
        fields: [
            { key: 'name', label: 'Name', placeholder: 'e.g. laptop-alice', hint: 'A friendly name for this peer.' },
            { key: 'tunnel', label: 'Tunnel', type: 'select', options: tunnelOpts, hint: 'Which VPN tunnel this peer connects to.' },
            { key: 'public_key', label: 'Public Key', placeholder: 'Peer\'s WireGuard public key',
              hint: 'Generate on client with: wg genkey | tee private.key | wg pubkey' },
            { key: 'preshared_key', label: 'Preshared Key (optional)', placeholder: 'Optional shared secret',
              hint: 'Adds extra symmetric-key encryption. Both sides must use the same key.' },
            { key: 'allowed_ips', label: 'Allowed IPs', placeholder: 'e.g. 10.0.0.2/32',
              hint: 'IPs this peer may use. Use /32 for a single client.' },
            { key: 'endpoint', label: 'Endpoint (optional)', placeholder: 'e.g. client.example.com:51820',
              hint: 'Peer\'s public IP:port. Leave empty if peer connects to you.' },
            { key: 'keepalive', label: 'Keepalive (seconds)', type: 'number', min: 0, max: 65535,
              hint: 'Send keepalive every N seconds. 25 is common for NAT traversal.' },
            { key: 'comment', label: 'Comment', placeholder: 'Optional note' }
        ],
        values: existing ? {
            name: existing.name || '', tunnel: existing.tunnel || '',
            public_key: existing.public_key || '', preshared_key: existing.preshared_key || '',
            allowed_ips: existing.allowed_ips || '', endpoint: existing.endpoint || '',
            keepalive: existing.keepalive || '', comment: existing.comment || ''
        } : {},
        submitLabel: existing ? 'Update' : 'Add Peer',
        onSubmit: async (data) => {
            if (!data.name.trim()) { notify('Name is required', 'error'); return; }
            if (!data.public_key.trim()) { notify('Public key is required', 'error'); return; }
            const ok = await doubleConfirm(existing ? 'Update Peer' : 'Add Peer',
                (existing ? 'Update' : 'Add') + ' peer "' + data.name + '"?',
                existing ? 'Update' : 'Add');
            if (!ok) return;
            const payload = { name: data.name, tunnel: data.tunnel, public_key: data.public_key,
                preshared_key: data.preshared_key, allowed_ips: data.allowed_ips,
                endpoint: data.endpoint, keepalive: data.keepalive ? Number(data.keepalive) : 0,
                comment: data.comment };
            const r = existing
                ? await API.put('vpn/peers/' + encodeURIComponent(existing.name), payload)
                : await API.post('vpn/peers', payload);
            notify(r.error ? r.message : 'Peer ' + (existing ? 'updated' : 'added'), r.error ? 'error' : 'success');
            if (!r.error && onDone) onDone();
        }
    });
}

/* ---------- Peer Config Modal ---------- */

async function showPeerConfig(peer) {
    let configText = '';
    try {
        const r = await API.get('vpn/peers/' + encodeURIComponent(peer.name) + '/config');
        configText = (r.data || {}).config || (typeof r.data === 'string' ? r.data : JSON.stringify(r.data, null, 2));
    } catch (e) { configText = 'Failed to load: ' + e.message; }

    showModal({
        title: 'Client Config: ' + peer.name,
        wide: true,
        body: html('div', {},
            html('div', { className: 'text-secondary', style: 'margin-bottom:10px;font-size:0.9rem' },
                'Copy this config to the client device. Save as ' + peer.name + '.conf'),
            html('pre', { style: 'max-height:400px' }, configText),
            html('button', { className: 'btn btn-primary', style: 'margin-top:10px',
                onClick: () => copyToClipboard(configText) }, 'Copy to Clipboard'))
    });
}
