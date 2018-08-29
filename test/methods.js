
if (typeof module === 'undefined') {
	module = {};
} else {
	Cyrup = require('./cyrup.js');
}

const TEXT = 'hello world';
const PASSWORD = 'secret';

module.exports = {

	async password () {

		console.time('key');
		const password = await Cyrup.key(PASSWORD);
		console.timeEnd('key');

		console.time('compare');
		const valid = await Cyrup.compare(PASSWORD, password);
		console.timeEnd('compare');

		console.log(`key: ${password}`);
		console.log(`compare: ${valid}`);
	},

	async crypt () {

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

	},

	async hash () {
		const item = 'hash is good for you?';
		const hash = await Cyrup.hash(item);
		console.log(`hash: ${hash}`);
	},

	async secret () {
		const secret = await Cyrup.secret();
		console.log(`secret: ${secret}`);
	},

	async random () {
		const random = await Cyrup.random(32);
		console.log(`random: ${random}`);
	}
};
