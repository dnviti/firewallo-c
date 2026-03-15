/* ============================================================
   Firewallo Component Library
   Vanilla JS UI components: html builder, tables, tabs, modals,
   toasts, collapsible sections, loading states
   ============================================================ */

// --- DOM Helper ---
function html(tag, attrs, ...children) {
    var el = document.createElement(tag);
    if (attrs) {
        for (var k in attrs) {
            if (!attrs.hasOwnProperty(k)) continue;
            var v = attrs[k];
            if (k === 'onclick' || k === 'onchange' || k === 'oninput' || k === 'onkeydown') {
                el.addEventListener(k.slice(2), v);
            } else if (k === 'className') {
                el.className = v;
            } else if (k === 'htmlFor') {
                el.setAttribute('for', v);
            } else {
                el.setAttribute(k, v);
            }
        }
    }
    for (var i = 0; i < children.length; i++) {
        var c = children[i];
        if (typeof c === 'string' || typeof c === 'number') {
            el.appendChild(document.createTextNode(String(c)));
        } else if (c && c.nodeType) {
            el.appendChild(c);
        }
    }
    return el;
}

// --- Toast Notifications ---
function notify(msg, type) {
    type = type || 'success';
    var container = document.getElementById('toast-container');
    var toast = html('div', { className: 'toast toast-' + type }, msg);
    container.appendChild(toast);
    setTimeout(function() {
        toast.classList.add('toast-exit');
        setTimeout(function() {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 300);
    }, 3500);
}

// --- Create Table ---
function createTable(headers, rows) {
    var table = html('table');
    var thead = html('thead');
    var tr = html('tr');
    headers.forEach(function(h) { tr.appendChild(html('th', {}, h)); });
    thead.appendChild(tr);
    table.appendChild(thead);

    var tbody = html('tbody');
    rows.forEach(function(row) {
        var r = html('tr');
        row.forEach(function(cell) {
            if (typeof cell === 'string' || typeof cell === 'number') {
                r.appendChild(html('td', {}, String(cell)));
            } else if (cell && cell.nodeType) {
                r.appendChild(html('td', {}, cell));
            } else {
                r.appendChild(html('td', {}, String(cell || '')));
            }
        });
        tbody.appendChild(r);
    });
    table.appendChild(tbody);
    return table;
}

// --- Filterable Table ---
function createFilterableTable(headers, rows, placeholder) {
    var container = html('div');

    var toolbar = html('div', { className: 'table-toolbar' });
    var searchInput = html('input', {
        className: 'table-search',
        type: 'text',
        placeholder: placeholder || 'Search...'
    });
    toolbar.appendChild(searchInput);
    container.appendChild(toolbar);

    var wrapper = html('div', { className: 'table-wrapper' });
    var table = createTable(headers, rows);
    wrapper.appendChild(table);
    container.appendChild(wrapper);

    searchInput.addEventListener('input', function() {
        var query = searchInput.value.toLowerCase();
        var trs = table.querySelectorAll('tbody tr');
        trs.forEach(function(tr) {
            var text = tr.textContent.toLowerCase();
            tr.style.display = text.indexOf(query) !== -1 ? '' : 'none';
        });
    });

    return container;
}

// --- Tab Bar ---
function createTabBar(tabs, onSelect) {
    var bar = html('div', { className: 'tab-bar' });
    var contentArea = html('div', { className: 'tab-content' });

    tabs.forEach(function(tab, index) {
        var btn = html('button', {
            className: 'tab-btn' + (index === 0 ? ' active' : ''),
            onclick: function() {
                bar.querySelectorAll('.tab-btn').forEach(function(b) {
                    b.classList.remove('active');
                });
                btn.classList.add('active');
                contentArea.innerHTML = '';
                if (onSelect) onSelect(tab.key, contentArea);
            }
        }, tab.label);
        if (tab.count !== undefined) {
            btn.appendChild(html('span', {
                className: 'badge badge-muted',
                style: 'margin-left:6px;font-size:0.72rem'
            }, String(tab.count)));
        }
        bar.appendChild(btn);
    });

    var container = html('div');
    container.appendChild(bar);
    container.appendChild(contentArea);

    // Trigger first tab
    if (tabs.length > 0 && onSelect) {
        onSelect(tabs[0].key, contentArea);
    }

    return container;
}

// --- Modal ---
function showModal(title, bodyContent, footerButtons) {
    var overlay = document.getElementById('modal-overlay');
    overlay.innerHTML = '';
    overlay.classList.remove('hidden');

    var modal = html('div', { className: 'modal' });

    var header = html('div', { className: 'modal-header' });
    header.appendChild(html('h3', {}, title));
    var closeBtn = html('button', {
        className: 'modal-close',
        onclick: hideModal
    }, '\u00D7');
    header.appendChild(closeBtn);
    modal.appendChild(header);

    var body = html('div', { className: 'modal-body' });
    if (typeof bodyContent === 'string') {
        body.appendChild(html('p', {}, bodyContent));
    } else if (bodyContent && bodyContent.nodeType) {
        body.appendChild(bodyContent);
    }
    modal.appendChild(body);

    if (footerButtons && footerButtons.length > 0) {
        var footer = html('div', { className: 'modal-footer' });
        footerButtons.forEach(function(fb) {
            footer.appendChild(html('button', {
                className: fb.className || 'btn',
                onclick: function() {
                    if (fb.onclick) fb.onclick();
                    if (fb.closeOnClick !== false) hideModal();
                }
            }, fb.label));
        });
        modal.appendChild(footer);
    }

    overlay.appendChild(modal);

    function overlayClickHandler(e) {
        if (e.target === overlay) {
            hideModal();
        }
    }
    overlay.addEventListener('click', overlayClickHandler);
    overlay._clickHandler = overlayClickHandler;
}

function hideModal() {
    var overlay = document.getElementById('modal-overlay');
    if (overlay._clickHandler) {
        overlay.removeEventListener('click', overlay._clickHandler);
        overlay._clickHandler = null;
    }
    overlay.classList.add('hidden');
    overlay.innerHTML = '';
}

// --- Confirm Dialog ---
function showConfirm(title, message, onConfirm, confirmLabel, confirmClass) {
    showModal(title, message, [
        { label: 'Cancel', className: 'btn' },
        {
            label: confirmLabel || 'Confirm',
            className: confirmClass || 'btn btn-primary',
            onclick: onConfirm
        }
    ]);
}

// --- Collapsible Section ---
function createCollapsible(title, contentFn, startOpen) {
    var section = html('div', { className: 'collapsible' + (startOpen ? ' open' : '') });

    var header = html('button', { className: 'collapsible-header' });
    var chevron = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    chevron.setAttribute('class', 'collapsible-chevron');
    chevron.setAttribute('viewBox', '0 0 24 24');
    chevron.setAttribute('width', '16');
    chevron.setAttribute('height', '16');
    chevron.setAttribute('fill', 'none');
    chevron.setAttribute('stroke', 'currentColor');
    chevron.setAttribute('stroke-width', '2');
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M9 18l6-6-6-6');
    chevron.appendChild(path);
    header.appendChild(chevron);
    header.appendChild(document.createTextNode(title));

    var bodyWrap = html('div', { className: 'collapsible-body' });
    var bodyContent = html('div', { className: 'collapsible-content' });
    bodyWrap.appendChild(bodyContent);

    header.addEventListener('click', function() {
        section.classList.toggle('open');
        if (section.classList.contains('open') && bodyContent.children.length === 0) {
            var content = contentFn();
            if (content && content.nodeType) bodyContent.appendChild(content);
        }
    });

    section.appendChild(header);
    section.appendChild(bodyWrap);

    // Populate if starting open
    if (startOpen) {
        var content = contentFn();
        if (content && content.nodeType) bodyContent.appendChild(content);
    }

    return section;
}

// --- Loading State ---
function createLoading(message) {
    return html('div', { className: 'loading' },
        html('div', { className: 'spinner' }),
        html('span', {}, message || 'Loading...')
    );
}

// --- Empty State ---
function createEmptyState(message) {
    return html('div', { className: 'empty-state' },
        html('div', { className: 'empty-icon' }, '--'),
        html('p', {}, message || 'No data available')
    );
}

// --- Stat Card ---
function createStatCard(value, label, iconClass, svgPath) {
    var card = html('div', { className: 'stat-card' });
    if (svgPath) {
        var iconWrap = html('div', { className: 'stat-icon ' + (iconClass || 'accent') });
        iconWrap.innerHTML = svgPath;
        card.appendChild(iconWrap);
    }
    card.appendChild(html('div', { className: 'stat-value' }, String(value)));
    card.appendChild(html('div', { className: 'stat-label' }, label));
    return card;
}

// --- Port Tag with Remove ---
function createPortTag(port, onRemove) {
    var tag = html('span', { className: 'port-tag' }, String(port));
    if (onRemove) {
        tag.appendChild(html('button', {
            className: 'remove-port',
            onclick: function(e) {
                e.stopPropagation();
                onRemove(port);
            }
        }, '\u00D7'));
    }
    return tag;
}
