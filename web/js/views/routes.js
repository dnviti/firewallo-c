/* ============================================================
   Firewallo — Routes View
   Static routing entries management
   ============================================================ */

async function renderRoutes() {
    view.innerHTML = '';
    view.appendChild(createLoading('Loading routes...'));

    async function refresh() {
        const cfgRes = await API.get('config');
        const routeList = (cfgRes.data || {}).routes || [];
        view.innerHTML = '';
        view.appendChild(createPageHeader('Static Routes', 'Manage static routing entries', [
            html('button', { className: 'btn btn-primary',
                onClick: () => showRouteModal(null, -1, refresh) }, '+ Add Route')]));
        if (routeList.length > 0) {
            const rows = routeList.map((r, i) => [
                r.destination || '-', r.gateway || '-', r.interface || '-', r.comment || '-',
                html('div', { className: 'btn-group' },
                    html('button', { className: 'btn btn-sm',
                        onClick: () => showRouteModal(r, i, refresh) }, 'Edit'),
                    html('button', { className: 'btn btn-sm btn-danger',
                        onClick: () => deleteRoute(i, refresh) }, 'Delete'))
            ]);
            view.appendChild(createFilterableTable(
                ['Destination', 'Gateway', 'Interface', 'Comment', 'Actions'], rows));
        } else {
            view.appendChild(html('div', { className: 'card' },
                html('div', { className: 'empty-state' },
                    html('div', { className: 'empty-state-icon' }, '\u2192'),
                    html('div', { className: 'empty-state-text' }, 'No static routes'),
                    html('button', { className: 'btn btn-primary',
                        onClick: () => showRouteModal(null, -1, refresh) }, '+ Add Route'))));
        }
    }

    await refresh();
    startPolling(refresh, 5000);
}

function showRouteModal(existing, index, onDone) {
    showFormModal({
        title: existing ? 'Edit Route' : 'Add Route',
        fields: [
            { key: 'destination', label: 'Destination', placeholder: 'e.g. 10.0.0.0/8' },
            { key: 'gateway', label: 'Gateway', placeholder: 'e.g. 192.168.1.1' },
            { key: 'interface', label: 'Interface', placeholder: 'e.g. eth0' },
            { key: 'comment', label: 'Comment', placeholder: 'Optional description' }
        ],
        values: existing ? { destination: existing.destination || '', gateway: existing.gateway || '',
            interface: existing.interface || '', comment: existing.comment || '' } : {},
        submitLabel: existing ? 'Update' : 'Add Route',
        onSubmit: async (data) => {
            if (!data.destination || !data.gateway) { notify('Destination and gateway required', 'error'); return; }
            const ok = await doubleConfirm(existing ? 'Update Route' : 'Add Route',
                `${existing ? 'Update' : 'Add'} this route?`, existing ? 'Update' : 'Add');
            if (!ok) return;
            const r = await API.mutateConfig(c => {
                if (!c.routes) c.routes = [];
                const route = { destination: data.destination, gateway: data.gateway,
                    interface: data.interface, comment: data.comment };
                if (index >= 0) c.routes[index] = route;
                else c.routes.push(route);
            });
            notify(r.ok ? 'Route saved' : r.message, r.ok ? 'success' : 'error');
            if (r.ok && onDone) onDone();
        }
    });
}

async function deleteRoute(index, onDone) {
    const ok = await doubleConfirm('Delete Route', 'Delete this route?', 'Delete', 'btn-danger');
    if (!ok) return;
    const r = await API.mutateConfig(c => { if (c.routes) c.routes.splice(index, 1); });
    notify(r.ok ? 'Route deleted' : r.message, r.ok ? 'success' : 'error');
    if (r.ok && onDone) onDone();
}
