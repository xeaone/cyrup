const Cyrup = require('../dis/cyrup.node.js');

(async function() {
	const password = 'secret';
	const text = 'hello world';

	const encrypted = await Cyrup.encrypt(password, text);
	// console.log(encrypted);

	const decrypted = await Cyrup.decrypt(password, encrypted);
	// console.log(decrypted);

}()).catch(function (error) {
	console.error(error);
});
