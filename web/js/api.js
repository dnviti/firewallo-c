const API = {
    base: '/api/v1',

    async get(path) {
        try {
            const res = await fetch(`${this.base}/${path}`);
            return res.json();
        } catch (e) {
            return { error: true, message: 'Network error: ' + e.message };
        }
    },

    async post(path, body) {
        try {
            const res = await fetch(`${this.base}/${path}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            return res.json();
        } catch (e) {
            return { error: true, message: 'Network error: ' + e.message };
        }
    },

    async del(path) {
        try {
            const res = await fetch(`${this.base}/${path}`, { method: 'DELETE' });
            return res.json();
        } catch (e) {
            return { error: true, message: 'Network error: ' + e.message };
        }
    }
};
