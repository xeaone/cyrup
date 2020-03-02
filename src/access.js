import Role from './role.js';

// {
//     resource: 'user',
//     action: 'update',
//     behavior: true,
//     requires: {
//         account: 'ACCOUNT',
//     },
//     allows: [
//         'firstName'
//     ],
//     denies: [
//         'lastName'
//     ]
// };

export default class Access {

    constructor (access = {}) {
        const { roles } = access;

        this._roles = {};

        if ('roles' in access) {
            if (roles instanceof Array === false) throw new Error('access roles illegal type');
            roles.forEach(role => this.role(role));
        }

    }

    role () {
        const role = new Role(...arguments);
        this.add(role);
        return role;
    }

    get (role) {

        if (role instanceof Role === false) throw new Error('access get requires role');

        const name = role.name();

        return this._roles[name];
    }

    add (role) {

        if (role instanceof Role === false) throw new Error('access add requires role');

        const name = role.name();
        const exists = name in this._roles;
        if (exists) throw new Error(`access add role ${name} exists`);

        this._roles[name] = role;

        return this;
    }

    remove (role) {

        if (role instanceof Role === false) throw new Error('access remove requires role');

        const name = role.name();
        const exists = name in this._roles;
        if (exists) throw new Error(`access remove role ${name} exists`);

        delete this._roles[name];

        return this;
    }

    roles () {
        return Object.freeze(this._roles);
    }

    toJSON () {
        return this._roles;
    }

}
