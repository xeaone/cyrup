
if (typeof module === 'undefined') {
	module = {};
} else {
	Cyrup = require('./cyrup.js');
}

const TEXT = 'hello world';
const PASSWORD = 'secret';

module.exports = {

	async password () {

		console.time('passwordHash');
		const password = await Cyrup.passwordHash(PASSWORD);
		console.timeEnd('passwordHash');

		console.time('passwordCompare');
		const valid = await Cyrup.passwordCompare(PASSWORD, password);
		console.timeEnd('passwordCompare');

		console.log(`passwordHash: ${password}`);
		console.log(`passwordCompare: ${valid}`);
	},

	async crypt () {

		console.time('key');
		const key = await Cyrup.key({ item: PASSWORD });
		console.timeEnd('key');

		console.time('encrypt');
		const encrypted = await Cyrup.encrypt({ item: TEXT, key: key });
		console.timeEnd('encrypt');

		console.time('decrypt');
		const decrypted = await Cyrup.decrypt({ item: encrypted, key: key });
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
