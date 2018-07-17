import Cyrup from './cyrup.js';

document.querySelector('.crypt').addEventListener('click', async function () {
	const password = 'secret';
	const text = 'hello wrold';

	const encrypted = await Cyrup.encrypt(password, text);
	console.log(`encrypted: ${encrypted}`);

	const decrypted = await Cyrup.decrypt(password, encrypted);
	console.log(`decrypted: ${decrypted}`);
});

document.querySelector('.hash').addEventListener('click', async function () {
	const hash = await Cyrup.hash('hash is good');
	console.log(hash);
});

document.querySelector('.secret').addEventListener('click', async function () {
	const secret = await Cyrup.secret();
	console.log(secret);
});
