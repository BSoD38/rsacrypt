const randomPrime = require('./utils').randomPrime;
const decompose = require('./utils').decompose;
fs = require('fs');
const bigInt = require('big-integer');

const args = process.argv.slice(2);

let fileName = "monRSA";
let input = null;
let output = null;

if (args.length === 0) {
    help();
    return;
}

if (args.indexOf("-o") !== -1 && args[args.indexOf("-o") + 1]) {
    output = args[args.indexOf("-o") + 1];
}

if (args.indexOf("-i") !== -1 && args[args.indexOf("-i") + 1]) {
    input = args[args.indexOf("-i") + 1];
}

switch (args[0]) {
    case "help":
    case "-h":
        help();
        return;
    case "keygen":
        if (args.indexOf("-f") !== -1 && args[args.indexOf("-f") + 1]) {
            fileName = parseFilename(args[2]);
        }
        let keySize = 32;
        if (args.indexOf("-s") !== -1 && args[args.indexOf("-s") + 1]) {
            keySize = parseInt(args[args.indexOf("-s") + 1]);
        }
        keygen(keySize);
        break;
    case "crypt":
        if (args[1] && (input || args[2])) {
            fileName = parseFilename(args[1]);
            if (fs.existsSync(`${fileName}.pub`)) {
                const data = crypt(input ? fs.readFileSync(input).toString() : args[2]);
                if (output) {
                    fs.writeFileSync(output, Buffer.from(data));
                    console.log(`Message has been encrypted into file ${output}.`);
                } else {
                    console.log(`Message has been encrypted. Encrypted message is "${data}"`);
                }
            } else {
                console.log("Given key file doesn't exist.");
            }
        } else {
            console.log("Invalid parameters.")
        }
        break;
    case "decrypt":
        if (args[1] && (input || args[2])) {
            fileName = parseFilename(args[1]);
            if (fs.existsSync(`${fileName}.priv`)) {
                const data = decrypt(input ? fs.readFileSync(input).toString() : args[2]);
                if (output) {
                    fs.writeFileSync(output, data);
                    console.log(`Decrypted message into file : "${output}"`);
                } else {
                    console.log(`Decrypted message : "${data}"`);
                }
            } else {
                console.log("Given key file doesn't exist.");
            }
        } else {
            console.log("Invalid parameters.");
        }
        break;
    default:
        console.log("Invalid command.");
        help();
        break;
}

function parseFilename(name) {
    return /.pub|.priv/.test(name) ? name.split(/.pub|.priv/)[0] : name;
}

function help() {
    console.log("Usage: node rsacrypt.js [command] [...options]");
    console.log("Available [command] are:");
    console.log("- keygen [...options]: Generates a key. Use option -f [filename] to specify a custom key file name. Use -s [size] to specify a key size (32 by default).");
    console.log("- crypt [key] [message] [...options]: Encrypts a message with the given key file. Use option -i to use a file as input. Use option -o to output encrypted data into a file.");
    console.log("- decrypt [key] [message] [...options]: Decrypts a message with the given key file. Use option -i to use a file as input. Use option -o to output the decrypted data into a file.");
    console.log("- help or -h: Shows this help screen.");
}

function keygen(keyLength) {
    console.log("Generating keys... This might take a while.");
    const p = randomPrime(keyLength / 2);
    let q = randomPrime(keyLength / 2);
    while (p === q) {
        q = randomPrime(keyLength / 2);
    }
    const n = p.multiply(q);
    const nPrime = p.minus(1).multiply(q.minus(1));
    let i = bigInt();
    let e = bigInt();
    let d = bigInt();
    while (true) {
        i = i.add(1);
        const temp = bigInt.one.add(i.multiply(nPrime));
        try {
            [e, d] = decompose(temp);
            if (e === d || !e || !d) {
                continue;
            }
            break;
        } catch (e) {console.log(e);}
    }
    fs.writeFileSync(
        `${fileName}.pub`,
        `---begin monRSA public key---\n${Buffer.from(`${n.toString(16)}\n${e.toString(16)}`).toString("base64")}\n---end monRSA key---`
    );
    fs.writeFileSync(
        `${fileName}.priv`,
        `---begin monRSA private key---\n${Buffer.from(`${n.toString(16)}\n${d.toString(16)}`).toString("base64")}\n---end monRSA key---`
    );
    console.log("Keys have been generated.");
}

function crypt(value) {
    const keyData = fs.readFileSync(`${fileName}.pub`).toString();
    if (!keyData.includes("---begin monRSA public key---")) {
        console.log("Key file is malformed. Please regenerate a new set of keys.");
        return;
    }
    const [nHex, eHex] = Buffer.from(keyData.split("\n")[1], "base64").toString().split("\n");
    const maxBlockSize = parseInt(nHex, 16).toString(10).length - 1;
    const encodedText = bytesToDec(stringToUTF8Bytes(value));
    const chunks = [];
    let position = encodedText.length;
    while (position >= 0) {
        position -= maxBlockSize;
        chunks.push(encodedText.substring(position < 0 ? 0 : position, position + maxBlockSize));
    }
    const encryptedChunks = [];
    for (const chunk of chunks) {
        encryptedChunks.push(bigInt(chunk).modPow(bigInt(eHex, 16), bigInt(nHex, 16)).toString(16).padStart(maxBlockSize, "0"));
    }
    return encryptedChunks.join("");
}

function decrypt(value) {
    const keyData = fs.readFileSync(`${fileName}.priv`).toString();
    if (!keyData.includes("---begin monRSA private key---")) {
        console.log("Key file is malformed. Please regenerate a new set of keys.");
        return;
    }
    const [nHex, dHex] = Buffer.from(keyData.split("\n")[1], "base64").toString().split("\n");
    const maxBlockSize = parseInt(nHex, 16).toString(10).length - 1;
    const chunks = [];
    for (let i = 0; i < value.length; i += maxBlockSize) {
        chunks.push(value.substring(i, i + maxBlockSize));
    }
    const decryptedChunks = [];
    for (const chunk of chunks) {
        decryptedChunks.push(bigInt(chunk, 16).modPow(bigInt(dHex, 16), bigInt(nHex, 16)).toString(10).padStart(maxBlockSize, "0"));
    }
    let encoded = decryptedChunks.reverse().join("");
    let buffer = new Uint8Array(0);
    let i = 0;
    for (let position = encoded.length; position > 0; position -= 3) {
        const byte = parseInt(encoded.substring(position - 3, position).padStart(3, "0"));
        if (byte > 0) {
            buffer = appendBytesToBuffer(buffer, [byte]);
        }
        i++;
    }
    return UTF8BytesToString(buffer.reverse());
}

function bytesToDec(bytes) {
    return Array.from(
        bytes,
        byte => byte.toString(10).padStart(3, "0")
    ).join("");
}

function stringToUTF8Bytes(string) {
    return new TextEncoder().encode(string);
}

function UTF8BytesToString(bytes) {
    return new TextDecoder().decode(bytes);
}

function appendBytesToBuffer(buffer, bytes) {
    const newBuffer = new Uint8Array(buffer.byteLength + 1);
    newBuffer.set(buffer, 0);
    newBuffer.set(bytes, buffer.byteLength);
    return newBuffer;
}
