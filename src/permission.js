
export default class Permission {

    constructor (permission = {}) {
        const {
            allows, denies, requires,
            action, resource, behavior
        } = permission;

        this._edit = true;
        this._action = null;
        this._resource = null;
        this._behavior = null;
        this._allows = [];
        this._denies = [];
        this._requires = {};

        if ('action' in permission) this.action(action);
        if ('resource' in permission) this.resource(resource);
        if ('behavior' in permission) this.behavior(behavior);

        if ('allows' in permission) {
            if (allows instanceof Array === false) throw new Error('permission allows illegal type');
            allows.forEach(allow => this.allow(allow));
        }

        if ('denies' in permission) {
            if (denies instanceof Array === false) throw new Error('permission denies illegal type');
            denies.forEach(deny => this.deny(deny));
        }

        if ('requires' in permission) {
            if (requires instanceof Object === false) throw new Error('permission requires illegal type');
            Object.entries(requires).forEach(([ name, value ]) => this.require(name, value));
        }

    }

    action (action) {

        if (action === undefined) return this._action;
        if (typeof action !== 'string') throw new Error('permission action string required');

        this._action = action;

        return this;
    }

    resource (resource) {

        if (resource === undefined) return this._resource;
        if (typeof resource !== 'string') throw new Error('permission resource string required');

        this._resource = resource;

        return this;
    }

    behavior (behavior) {
        
        if (behavior === undefined) return this._behavior;
        if (typeof behavior !== 'boolean') throw new Error('permission behavior boolean required');

        this._behavior = behavior;

        return this;
    }

    allow (allow) {

        if (allow === undefined) return this._allows;
        if (typeof allow !== 'string') throw new Error('permission allow string required');

        const exists = this._allows.includes(allow);
        if (exists) throw new Error(`permission allow ${allow} exists`);

        this._allows.push(allow);

        return this;
    }

    deny (deny) {

        if (deny === undefined) return this._denies;
        if (typeof deny !== 'string') throw new Error('permission deny string required');

        const exists = this._denies.includes(deny);
        if (exists) throw new Error(`permission deny ${deny} exists`);

        this._denies.push(deny);

        return this;
    }

    require (name, value) {

        if (name === undefined && value === undefined) return this._requires;
        if (typeof name !== 'string') throw new Error('permission name string required');
        if (typeof value !== 'string') throw new Error('permission value string required');

        this._requires[name] = value;

        return this;
    }

    edit (edit) {

        if (edit === undefined) return this._edit;
        if (typeof edit !== 'boolean') throw new Error('permission edit boolean required');

        this._edit = edit;

        return this;
    }

    validate () {

        if (typeof this._action !== 'string') throw new Error('permission action required');
        if (typeof this._resource !== 'string') throw new Error('permission resource required');
        if (typeof this._behavior !== 'boolean') throw new Error('permission behavior required');

        return this;
    }

    valid () {

        if (typeof this._action !== 'string') return false;
        if (typeof this._resource !== 'string') return false;
        if (typeof this._behavior !== 'boolean') return false;

        return true;
    }

    toJSON () {
        return {
            action: this._action,
            resource: this._resource,
            behavior: this._behavior,
            allows: this._allows,
            denies: this._denies,
            requires: this._requires
        };
    }

}
