import Role from './role.js';
import Permission from './permission.js';

// access
//     .permission()
//     .behavior(true)
//     .resource('user')
//     .action('update')
//     .allow('firstName')
//     .deny('lastName')
//     .require('account', account);

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

    constructor () {
        this._roles = {};
    }

    permission (permission) {
        return new Permission(permission);
    }

    role (role) {
        return new Role(role);
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

    validate (resource, action, data) {

    }

    roles () {
        return Object.freeze(this._roles);
    }

    toJSON () {
        return this._roles;
    }

}
