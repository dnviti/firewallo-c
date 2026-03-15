/* ============================================================
   Firewallo — Theme, Sidebar, Header Status, Polling
   Shell infrastructure shared by all views
   ============================================================ */

// ---- Polling system ----
let activePoller = null;

function startPolling(fn, interval) {
    stopPolling();
    activePoller = setInterval(fn, interval || 5000);
}

function stopPolling() {
    if (activePoller) {
        clearInterval(activePoller);
        activePoller = null;
    }
}

// ---- Double confirmation helper ----
async function doubleConfirm(title, message, actionLabel, actionClass) {
    const first = await confirm(title, message, actionLabel, actionClass || 'btn-primary');
    if (!first) return false;
    const second = await confirm(
        'Final Confirmation',
        'This change will be applied to the running configuration immediately. Proceed?',
        'Apply Now', actionClass || 'btn-primary'
    );
    return second;
}

// ---- Theme management ----
function initTheme() {
    const saved = localStorage.getItem('fw-theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
        document.documentElement.setAttribute('data-theme', 'light');
    }
    updateThemeIcon();
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('fw-theme', next);
    updateThemeIcon();
}

function updateThemeIcon() {
    const btn = document.getElementById('theme-toggle');
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    btn.innerHTML = isLight ? '&#9728;' : '&#9790;';
}

// ---- Sidebar mobile toggle ----
function initSidebar() {
    const hamburger = document.getElementById('hamburger-btn');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    hamburger.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('visible');
    });

    overlay.addEventListener('click', () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('visible');
    });

    sidebar.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                sidebar.classList.remove('open');
                overlay.classList.remove('visible');
            }
        });
    });
}

// ---- Header status (real-time) ----
async function updateHeaderStatus() {
    try {
        const res = await API.get('firewall/status');
        const s = res.data || {};
        const dot = document.getElementById('status-dot');
        const text = document.getElementById('status-text');
        dot.className = 'status-dot ' + (s.active ? 'active' : 'inactive');
        text.textContent = s.active ? 'Active' : 'Inactive';
    } catch (e) {
        document.getElementById('status-text').textContent = 'Offline';
    }
}

async function updateSidebarVersion() {
    try {
        const res = await API.get('version');
        const v = (res.data || {}).version || '?';
        document.getElementById('sidebar-version').textContent = `Firewallo v${v}`;
    } catch (e) { /* ignore */ }
}

// ---- Global search ----
function initSearch() {
    document.getElementById('global-search').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            const q = e.target.value.trim();
            if (!q) return;
            location.hash = '#filter';
        }
    });
}

// ---- Port formatting helpers (shared by filter, DPI views) ----
function parsePortInput(val) {
    if (!val || val === '' || val === 'any') return 'any';
    if (val.includes(':')) return val;
    const n = parseInt(val);
    return isNaN(n) ? 'any' : n;
}

function formatPort(val) {
    if (val === undefined || val === null) return '';
    if (typeof val === 'object' && val.start !== undefined) {
        if (val.start === 0) return '';
        if (val.end > 0) return `${val.start}:${val.end}`;
        return String(val.start);
    }
    if (val === 'any' || val === 0) return '';
    return String(val);
}
