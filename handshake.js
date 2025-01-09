const { randomBytes, generateKeyPairSync, publicEncrypt, privateDecrypt, createHash, createCipheriv, createDecipheriv } = require('crypto');

function clientInitiateHandshake() {
    const clientHello = randomBytes(32).toString('hex');
    const serverResponse = serverRespondToClient(clientHello);
    return { clientHello, serverResponse };
}

function serverRespondToClient(clientHello) {
    const serverHello = randomBytes(32).toString('hex');

    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    serverPrivateKey = privateKey;

    return {
        serverHello,
        publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' }),
    };
}

function clientSendPremasterSecret(serverPublicKey) {
    const premasterSecret = randomBytes(32).toString('hex');
    console.log("Premaster Secret Client:", premasterSecret);

    const encryptedPremaster = publicEncrypt(
        {
            key: serverPublicKey,
            oaepHash: 'sha256',
        },
        Buffer.from(premasterSecret, 'utf8')
    );

    serverReceivePremasterSecret(encryptedPremaster);
    return premasterSecret;
}

function serverReceivePremasterSecret(encryptedPremaster) {
    const decryptedPremaster = privateDecrypt(
        {
            key: serverPrivateKey,
            oaepHash: 'sha256',
        },
        encryptedPremaster
    ).toString('utf8');

    console.log("Premaster Secret Server:", decryptedPremaster);
    serverPremasterSecret = decryptedPremaster;
}

function generateSessionKey(clientHello, serverHello, premasterSecret) {
    const keyMaterial = clientHello + serverHello + premasterSecret;
    const sessionKey = createHash('sha256').update(keyMaterial).digest();
    return sessionKey;
}

const encMethod = 'aes-256-cbc';

function encryptMessage(key, message) {
    const encIv = randomBytes(16);
    const cipher = createCipheriv(encMethod, key, encIv);
    const encrypted = Buffer.concat([encIv, cipher.update(message, 'utf8'), cipher.final()]);
    return encrypted;
}

function decryptMessage(key, encryptedMessage) {
    const iv = encryptedMessage.slice(0, 16);
    const encryptedText = encryptedMessage.slice(16);
    const decipher = createDecipheriv(encMethod, key, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString('utf8');
}

function clientReady(key) {
    const readyMessage = "готовий";
    const encryptedReadyMessage = encryptMessage(key, readyMessage);
    console.log("Client ready")
    serverConfirmReady(encryptedReadyMessage, key);
}

function serverConfirmReady(encryptedReadyMessage, key) {
    const decryptedMessage = decryptMessage(key, encryptedReadyMessage);

    if (decryptedMessage === "готовий") {
        const serverReadyMessage = encryptMessage(key, "готовий");
        console.log("Server ready")
        clientConfirmReady(serverReadyMessage, key);
    }
}

function clientConfirmReady(encryptedReadyMessage, key) {
    const decryptedMessage = decryptMessage(key, encryptedReadyMessage);

    if (decryptedMessage === "готовий") {
        console.log("Client received Server ready");
    }
}

function clientSendMessage(key, message) {
    const encryptedMessage = encryptMessage(key, message);
    console.log("Client encrypted message:", encryptedMessage.toString('hex'));
    serverReceiveMessage(key, encryptedMessage);
}

function serverReceiveMessage(key, encryptedMessage) {
    const decryptedMessage = decryptMessage(key, encryptedMessage);
    console.log("Server decrypted message:", decryptedMessage);
}


//////////////////////////////////

let serverPrivateKey;
const handshakeData = clientInitiateHandshake();

console.log("Client Hello:", handshakeData.clientHello);
console.log("Server Hello:", handshakeData.serverResponse.serverHello);
console.log("Public key:", handshakeData.serverResponse.publicKey);

const premasterSecret = clientSendPremasterSecret(handshakeData.serverResponse.publicKey);

const clientSessionKey = generateSessionKey(
    handshakeData.clientHello,
    handshakeData.serverResponse.serverHello,
    premasterSecret
);

const serverSessionKey = generateSessionKey(
    handshakeData.clientHello,
    handshakeData.serverResponse.serverHello,
    serverPremasterSecret
);

console.log("Session keys equal: ", clientSessionKey.equals(serverSessionKey));

clientReady(clientSessionKey);

clientSendMessage(clientSessionKey, "Привіт, як справи?");