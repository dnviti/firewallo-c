function notify(msg, type = 'success') {
    const el = document.getElementById('notification');
    el.textContent = msg;
    el.className = type;
    setTimeout(() => el.className = 'hidden', 3000);
}

function html(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'onclick') el.addEventListener('click', v);
        else if (k === 'className') el.className = v;
        else el.setAttribute(k, v);
    }
    for (const c of children) {
        if (typeof c === 'string') el.appendChild(document.createTextNode(c));
        else if (c) el.appendChild(c);
    }
    return el;
}

function createTable(headers, rows) {
    const table = html('table');
    const thead = html('thead');
    const tr = html('tr');
    headers.forEach(h => tr.appendChild(html('th', {}, h)));
    thead.appendChild(tr);
    table.appendChild(thead);

    const tbody = html('tbody');
    rows.forEach(row => {
        const tr = html('tr');
        row.forEach(cell => {
            if (typeof cell === 'string' || typeof cell === 'number')
                tr.appendChild(html('td', {}, String(cell)));
            else
                tr.appendChild(html('td', {}, cell));
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
}
