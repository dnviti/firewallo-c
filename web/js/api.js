const API = {
    base: '/api/v1',

    async get(path) {
        try {
            const res = await fetch(`${this.base}/${path}`, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            return res.json();
        } catch (e) {
            return { error: true, message: 'Network error: ' + e.message };
        }
    },

    async post(path, body) {
        try {
            const res = await fetch(`${this.base}/${path}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(body)
            });
            return res.json();
        } catch (e) {
            return { error: true, message: 'Network error: ' + e.message };
        }
    },

    async put(path, body) {
        try {
            const res = await fetch(`${this.base}/${path}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(body)
            });
            return res.json();
        } catch (e) {
            return { error: true, message: 'Network error: ' + e.message };
        }
    },

    async del(path) {
        try {
            const res = await fetch(`${this.base}/${path}`, {
                method: 'DELETE',
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            return res.json();
        } catch (e) {
            return { error: true, message: 'Network error: ' + e.message };
        }
    },

    /**
     * Read-modify-write helper for config mutations.
     * Reads the full config, applies the mutator function, then PUTs it back.
     * Returns { ok: true } or { ok: false, message: string }.
     */
    async mutateConfig(mutator) {
        const res = await this.get('config');
        if (res.error) return { ok: false, message: res.message || 'Failed to read config' };
        const cfg = res.data;
        try {
            mutator(cfg);
        } catch (e) {
            return { ok: false, message: e.message || 'Mutation error' };
        }
        const putRes = await this.put('config', cfg);
        if (putRes.error) return { ok: false, message: putRes.message || 'Failed to save config' };
        return { ok: true };
    }
};
