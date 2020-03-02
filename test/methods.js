
if (typeof module === 'undefined') {
    var module = {};
} else {
    var Cyrup = require('./cyrup.js');
}

const TEXT = 'hello world';
const PASSWORD = 'secret';

const password = async function () {

    console.time('key');
    const password = await Cyrup.key(PASSWORD);
    console.timeEnd('key');

    console.time('compare');
    const valid = await Cyrup.compare(PASSWORD, password);
    console.timeEnd('compare');

    console.log(`key: ${password}`);
    console.log(`compare: ${valid}`);
};

const crypt = async function () {

    console.time('key');
    const key = await Cyrup.key(PASSWORD);
    console.timeEnd('key');

    console.time('encrypt');
    const encrypted = await Cyrup.encrypt(TEXT, key);
    console.timeEnd('encrypt');

    console.time('decrypt');
    const decrypted = await Cyrup.decrypt(encrypted, key);
    console.timeEnd('decrypt');

    console.log(`key: ${key}`);
    console.log(`encrypted: ${encrypted}`);
    console.log(`decrypted: ${decrypted}`);

};

const key = async function () {

    console.time('key');
    const key = await Cyrup.key(PASSWORD);
    console.timeEnd('key');

    console.log(`key: ${key}`);
};

const hash = async function () {
    const item = 'hash is good for you?';
    const hash = await Cyrup.hash(item);
    console.log(`hash: ${hash}`);
};

const random = async function () {
    const random = await Cyrup.random(32);
    console.log(`random: ${random}`);
};

const role = async function () {

    const data = {
        foo: 'a',
        bar: {
            baz: 'b'
        },
        account: '123'
    };

     const permission = Cyrup.permission()
        .action('put')
        .behavior(true)
        .deny('bar.baz')
        .resource('/user')
        .require('account', '123');
    console.log('permission: ', JSON.stringify(permission, null, '\t'));

    const role = Cyrup.role()
        .name('account')
        .active(true)
        .add(permission)
    console.log('role: ', JSON.stringify(role, null, '\t'));

    const result = role.validate('/user', 'put', data);
    console.log('validate: ', result);
    // role.validate('/user', 'put', data);

};

module.exports = { random, hash, key, crypt, password, role };
