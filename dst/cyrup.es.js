
/*
    Name: cyrup
    Version: 0.8.1
    License: MPL-2.0
    Author: Alexander Elias
    Email: alex.steven.elias@gmail.com
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

class Permission {

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

    edit (edit) {

        if (edit === undefined) return this._edit;
        if (typeof edit !== 'boolean') throw new Error('permission edit boolean required');

        this._edit = edit;

        return this;
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

    allows () {
        return Object.freeze(this._allows);
    }

    allow (allow) {

        if (typeof allow !== 'string') throw new Error('permission allow string required');

        const exists = this._allows.includes(allow);
        if (exists) throw new Error(`permission allow ${allow} exists`);

        this._allows.push(allow);

        return this;
    }

    denies () {
        return Object.freeze(this._deniess);
    }

    deny (deny) {

        if (typeof deny !== 'string') throw new Error('permission deny string required');

        const exists = this._denies.includes(deny);
        if (exists) throw new Error(`permission deny ${deny} exists`);

        this._denies.push(deny);

        return this;
    }

    requires () {
        return Object.freeze(this._requires);
    }

    require (name, value) {

        if (typeof name !== 'string') throw new Error('permission name string required');

        if (!(
            typeof value !== 'boolean' ||
            typeof value !== 'number' ||
            typeof value !== 'string' ||
            value instanceof Array
        )) throw new Error('permission value string or array required');

        this._requires[name] = value;

        return this;
    }

    traverse (name, data) {
        const keys = name.split('.');
        const last = keys.pop();
        keys.forEach(key => data = data[key]);
        return [ last, data ];
    }

    validate (resource, action, data) {

        if (typeof data !== 'object') return false;
        if (typeof action !== 'string') return false;
        if (typeof resource !== 'string') return false;

        if (this._action !== action) return false;
        if (this._resource !== resource) return false;

        for (const name in this._requires) {
            const [ key, reference ] = this.traverse(name, data);
            const internal = this._requires[key];
            const external = reference[key];
            if (key in reference) {
                if (
                    internal instanceof Array &&
                    internal.includes(external) ||
                    internal === external
                ) {
                    continue;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        if (this._behavior) {
            for (const name of this._denies) {
                const [ key, reference ] = this.traverse(name, data);
                if (key in reference) {
                    return false;
                } else {
                    continue;
                }
            }
        } else {
            for (const name of this._allows) {
                const [ key, reference ] = this.traverse(name, data);
                if (key in reference) {
                    return false;
                } else {
                    continue;
                }
            }
        }

        return true;
    }

    valid () {

        if (typeof this._action !== 'string') return false;
        if (typeof this._resource !== 'string') return false;
        if (typeof this._behavior !== 'boolean') return false;

        return true;
    }

    toJSON () {
        return {
            edit: this._edit,
            action: this._action,
            resource: this._resource,
            behavior: this._behavior,
            allows: this._allows,
            denies: this._denies,
            requires: this._requires
        };
    }

}

class Role {

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

class Access {

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

const Cyrup = {

    ENCODING: 'hex',
    ITERATIONS: 999999,

    KEY: 32,
    TAG: 16,
    SALT: 16,
    VECTOR: 12,
    RANDOM: 20,
    HASH: 'sha-512',
    ALGORITHM: 'aes-256-gcm',

    Role,
    Access,
    Permission,

    role () {
        return new Role(...arguments);
    },

    access () {
        return new Access(...arguments);
    },

    permission () {
        return new Permission(...arguments);
    },

    async random (size) {
        const self = this;

        size = size || self.RANDOM;

        const buffer = await self.randomBytes(size);
        const hex = await self.bufferToHex(buffer);

        return hex;
    },

    async hash (item, type) {
        const self = this;

        if (!item) throw new Error('Cyrup.hash - item argument required');

        type = self.normalizeHash(type || self.HASH);

        const buffer = await self.stringToBuffer(item);
        const bufferHash = await self.createHash(buffer, type);
        const hex = await self.bufferToHex(bufferHash);

        return hex;
    },

    async compare (password, key) {
        const self = this;

        if (!key) throw new Error('Cyrup.compare - key argument required');
        if (!password) throw new Error('Cyrup.compare - password argument required');

        const salt = await self.hexToBuffer(key.split(':')[1]);
        const data = await self.key(password, { salt });

        return data === key;
    },

    async key (item, data) {
        const self = this;

        if (!item) throw new Error('Cyrup.key - item argument required');

        data = data || {};
        data.size = data.size || self.KEY;
        data.salt = data.salt || self.SALT;
        data.iterations = data.iterations || self.ITERATIONS;
        data.hash = self.normalizeHash(data.hash || self.HASH);

        const [ bItem, bSalt ] = await Promise.all([

            typeof item === 'string' ?
                self.stringToBuffer(item) : item,

            typeof data.salt === 'string' ?
                self.stringToBuffer(data.salt) :
                typeof data.salt === 'number' ?
                    self.randomBytes(data.salt) :
                    data.salt

        ]);

        const bKey = await self.pbkdf2(bItem, bSalt, data.iterations, data.size, data.hash);

        const [ hKey, hSalt ] = await Promise.all([
            self.bufferToHex(bKey),
            self.bufferToHex(bSalt)
        ]);

        return `${hKey}:${hSalt}`;
    },

    async encrypt (data, key, algorithm, vector) {
        const self = this;

        if (!key) throw new Error('Cyrup.encrypt - key argument required');
        if (!data) throw new Error('Cyrup.encrypt - data argument required');

        key = key.split(':');
        vector = vector || self.VECTOR;
        algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

        const [ bKey, bData, bVector ] = await Promise.all([
            self.hexToBuffer(key[0]),
            typeof data === 'string' ? self.stringToBuffer(data) : data,
            typeof vector === 'string' ? self.stringToBuffer(vector) : self.randomBytes(vector)
        ]);

        const bEncrypted = await self.cipher(algorithm, bKey, bVector, bData);

        const [ hEncrypted, hVector ] = await Promise.all([
            self.bufferToHex(bEncrypted),
            self.bufferToHex(bVector)
        ]);

        return `${hEncrypted}:${hVector}`;
    },

    async decrypt (data, key, algorithm) {
        const self = this;

        if (!key) throw new Error('Cyrup.decrypt - key argument required');
        if (!data) throw new Error('Cyrup.decrypt - data argument required');

        algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

        key = key.split(':');
        data = data.split(':');

        const [ bKey, bData, bVector ] = await Promise.all([
            self.hexToBuffer(key[0]),
            self.hexToBuffer(data[0]),
            self.hexToBuffer(data[1])
        ]);

        const bDecrypted = await self.decipher(algorithm, bKey, bVector, bData);
        const sDecrypted = await self.bufferToString(bDecrypted);

        return sDecrypted;
    }

};

if (typeof window === 'undefined') {

    const Util = require('util');
    const Crypto = require('crypto');
    const Pbkdf2 = Util.promisify(Crypto.pbkdf2);
    const RandomBytes = Util.promisify(Crypto.randomBytes);

    Cyrup.normalizeHash = function (hash) {
        return hash.replace('-', '').toLowerCase();
    };

    Cyrup.normalizeAlgorithm = function (algorithm) {
        if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
        return algorithm.toLowerCase();
    };

    Cyrup.hexToBuffer = async function (hex) {
        return Buffer.from(hex, 'hex');
    };

    Cyrup.bufferToHex = async function (buffer) {
        return buffer.toString('hex');
    };

    Cyrup.stringToBuffer = async function (string) {
        return Buffer.from(string, 'utf8');
    };

    Cyrup.bufferToString = async function (buffer) {
        return buffer.toString('utf8');
    };

    Cyrup.createHash = async function (buffer, type) {
        return Crypto.createHash(type).update(buffer).digest();
    };

    Cyrup.randomBytes = async function (bytes) {
        return RandomBytes(bytes);
    };

    Cyrup.pbkdf2 = async function (password, salt, iterations, size, hash) {
        return Pbkdf2(password, salt, iterations, size, hash);
    };

    Cyrup.cipher = async function (algorithm, key, vector, data) {
        const cipher = Crypto.createCipheriv(algorithm, key, vector);
        return Buffer.concat([ cipher.update(data, 'utf8'), cipher.final(), cipher.getAuthTag() ]);
    };

    Cyrup.decipher = async function (algorithm, key, vector, data) {
        const self = this;
        const buffer = Buffer.from(data, 'hex');
        const tag = buffer.slice(buffer.byteLength - self.TAG);
        const text = buffer.slice(0, buffer.byteLength - self.TAG);
        const decipher = Crypto.createDecipheriv(algorithm, key, vector);

        decipher.setAuthTag(tag);

        return Buffer.concat([ decipher.update(text), decipher.final() ]);
    };

} else {

    Cyrup.normalizeHash = function (hash) {
        return hash.toUpperCase();
    };

    Cyrup.normalizeAlgorithm = function (algorithm) {
        if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
        const algorithms = algorithm.split('-');
        return (algorithms[0] + '-' + algorithms[2]).toUpperCase();
    };

    Cyrup.getAuthTag = function (encrypted) {
        return encrypted.slice(encrypted.byteLength - this.TAG);
    };

    Cyrup.hexToBuffer = async function (hex) {

        if (typeof hex !== 'string') {
            throw new TypeError('Cyrup.hexToBuffer - expected input to be a string');
        }

        if ((hex.length % 2) !== 0) {
            throw new RangeError('Cyrup.hexToBuffer - expected string to be an even number of characters');
        }

        const bytes = new Uint8Array(hex.length / 2);

        for (let i = 0, l = hex.length; i < l; i += 2) {
            bytes[i/2] = parseInt( hex.substring(i, i + 2), 16 );
        }

        return bytes.buffer;
    };

    Cyrup.bufferToHex = async function (buffer) {
        const bytes = new Uint8Array(buffer);
        const hex = new Array(bytes.length);

        for (let i = 0, l = bytes.length; i < l; i++) {
            hex[i] = ( '00' + bytes[i].toString(16) ).slice(-2);
        }

        return hex.join('');
    };

    Cyrup.stringToBuffer = async function (string) {
        const bytes = new Uint8Array(string.length);

        for (let i = 0, l = string.length; i < l; i++) {
            bytes[i] = string.charCodeAt(i);
        }

        return bytes.buffer;
    };

    Cyrup.bufferToString = async function (buffer) {
        const bytes = new Uint8Array(buffer);
        const string = new Array(bytes.length);

        for (let i = 0, l = bytes.length; i < l; i++) {
            string[i] = String.fromCharCode(bytes[i]);
        }

        return string.join('');
    };

    Cyrup.createHash = async function (buffer, type) {
        return window.crypto.subtle.digest(type, buffer);
    };

    Cyrup.randomBytes = async function (size) {
        return window.crypto.getRandomValues(new Uint8Array(size));
    };

    Cyrup.pbkdf2 = async function (password, salt, iterations, size, hash) {
        const key = await window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, [ 'deriveBits' ]);

        const bits = await window.crypto.subtle.deriveBits({
            salt,
            iterations,
            name: 'PBKDF2',
            hash: { name: hash }
        }, key, size << 3);

        return new Uint8Array(bits);
    };

    Cyrup.cipher = async function (algorithm, key, vector, data) {
        const self = this;

        const oKey = await window.crypto.subtle.importKey('raw', key, {
            name: algorithm
        }, false, [ 'encrypt' ]);

        const encrypted = await window.crypto.subtle.encrypt({
            iv: vector,
            name: algorithm,
            tagLength: self.TAG * 8
        }, oKey, data);

        return encrypted;
    };

    Cyrup.decipher = async function (algorithm, key, vector, data) {
        const self = this;

        const oKey = await window.crypto.subtle.importKey('raw', key, {
            name: algorithm
        }, false, [ 'decrypt' ]);

        const decrypted = await window.crypto.subtle.decrypt({
            iv: vector,
            name: algorithm,
            tagLength: self.TAG * 8
        }, oKey, data);

        return decrypted;
    };

}

export default Cyrup;
