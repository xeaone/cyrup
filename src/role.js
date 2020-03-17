import Permission from './permission.js';

export default class Role {

    constructor (role = {}) {

        const {
            name, active, permissions
        } = role;

        this._edit = true;
        this._name = null;
        this._active = null;
        this._permissions = [];

        if ('name' in role) this.name(name);
        if ('active' in role) this.active(active);

        if ('permissions' in role) {
            if (permissions instanceof Array === false) throw new Error('role permissions illegal type');
            permissions.forEach(permission => this.permission(permission));
        }

    }

    edit (edit) {

        if (edit === undefined) return this._edit;
        if (typeof edit !== 'boolean') throw new Error('role edit boolean required');

        this._edit = edit;

        return this;
    }

    name (name) {

        if (name === undefined) return this._name;
        if (typeof name !== 'string') throw new Error('role name string required');

        this._name = name;

        return this;
    }

    active (active) {

        if (active === undefined) return this._active;
        if (typeof active !== 'boolean') throw new Error('role active boolean required');

        this._active = active;

        return this;
    }

    permissions () {
        return Object.freeze(this._permissions);
    }

    permission  () {
        const permission = new Permission(...arguments);
        this.add(permission);
        return permission;
    }

    get (resource, action) {
        return this._permissions.find(
            permission =>
                permission.action() === action &&
                permission.resource() === resource
        );
    }

    add (permission) {

        if (permission instanceof Permission === false) throw new Error('role add requires permission');
        // if (permission.valid() === false) throw new Error('role add permission invalid');

        const action = permission.action();
        const resource = permission.resource();

        const exists = this._permissions.find(({ _resource, _action }) => {
            return _resource === resource && _action === action;
        });

        if (exists) throw new Error(`role add permission ${resource} ${action} exists`);

        this._permissions.push(permission);

        return this;
    }

    validate (resource, action, data) {

        if (typeof data !== 'object') return false;
        if (typeof action !== 'string') return false;
        if (typeof resource !== 'string') return false;

        if (this._active === false) return false;

        const permission = this.get(resource, action);
        if (!permission) return false;

        return permission.validate(resource, action, data);
    }

    valid () {

        if (typeof this._name !== 'string') return false;
        if (typeof this._active !== 'boolean') return false;

        for (const permission of this._permissions) {
            if (permission.valid() === false) {
                return false;
            }
        }

        return true;
    }

    toJSON () {
        return {
            edit: this._edit,
            name: this._name,
            active: this._active,
            permissions: this._permissions.map(permission => permission.toJSON())
        };
    }

}
