var unorm = require("unorm");
var assert = require("assert");
var pbkdf2 = require("react-native-fast-crypto").pbkdf2;
var createHash = require("create-hash");
import { generateSecureRandom } from "react-native-securerandom";

declare type RandomNumberGenerator = (
  size: number,
  callback: (err: Error | null, buf: Buffer) => void
) => void;

var DEFAULT_WORDLIST = require("../wordlists/en.json");
var SPANISH_WORDLIST = require("../wordlists/es.json");

async function mnemonicToSeed(mnemonic: string, password: string) {
  var mnemonicBuffer = Buffer.from(mnemonic, "utf8");
  var saltBuffer = Buffer.from(salt(password), "utf8");
  return await pbkdf2.deriveAsync(
    mnemonicBuffer,
    saltBuffer,
    2048,
    64,
    "sha512"
  );
}

async function mnemonicToSeedHex(mnemonic: string, password: string) {
  var seed = await mnemonicToSeed(mnemonic, password);
  return seed.toString("hex");
}

function mnemonicToEntropy(mnemonic: string, wordlist: string[]) {
  wordlist = wordlist || DEFAULT_WORDLIST;

  var words = mnemonic.split(" ");
  assert(words.length % 3 === 0, "Invalid mnemonic");

  var belongToList = words.every(function (word) {
    return wordlist.indexOf(word) > -1;
  });

  assert(belongToList, "Invalid mnemonic");

  // convert word indices to 11 bit binary strings
  var bits = words
    .map(function (word) {
      var index = wordlist.indexOf(word);
      return lpad(index.toString(2), "0", 11);
    })
    .join("");

  // split the binary string into ENT/CS
  var dividerIndex = Math.floor(bits.length / 33) * 32;
  var entropy = bits.slice(0, dividerIndex);
  var checksum = bits.slice(dividerIndex);

  // calculate the checksum and compare
  var entropyBytes = (entropy.match(/(.{1,8})/g) as Array<string>).map(
    function (bin) {
      return parseInt(bin, 2);
    }
  );
  var entropyBuffer = Buffer.from(entropyBytes);
  var newChecksum = checksumBits(entropyBuffer);

  assert(newChecksum === checksum, "Invalid mnemonic checksum");

  return entropyBuffer.toString("hex");
}

function entropyToMnemonic(entropy: string, wordlist: string[]) {
  wordlist = wordlist || DEFAULT_WORDLIST;

  var entropyBuffer = Buffer.from(entropy, "hex");
  var entropyBits = bytesToBinary([].slice.call(entropyBuffer));
  var checksum = checksumBits(entropyBuffer);

  var bits = entropyBits + checksum;
  var chunks = bits.match(/(.{1,11})/g);

  var words = chunks.map(function (binary: string) {
    var index = parseInt(binary, 2);

    return wordlist[index];
  });

  return words.join(" ");
}

function generateMnemonic(
  strength?: number,
  rng?: RandomNumberGenerator,
  wordlist?: string[]
) {
  return new Promise((resolve, reject) => {
    strength = strength || 128;
    rng = rng || generateSecureRandom;
    generateSecureRandom(strength / 8)
      .then((bytes) => {
        if (!wordlist) {
          throw new Error("No wordlist");
        }
        const hexBuffer = Buffer.from(bytes).toString("hex");
        resolve(entropyToMnemonic(hexBuffer, wordlist));
      })
      .catch((err) => {
        reject(err);
      });
  });
}

function validateMnemonic(mnemonic: string, wordlist: string[]) {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
}

function checksumBits(entropyBuffer: Buffer) {
  var hash = createHash("sha256").update(entropyBuffer).digest();

  // Calculated constants from BIP39
  var ENT = entropyBuffer.length * 8;
  var CS = ENT / 32;

  return bytesToBinary([].slice.call(hash)).slice(0, CS);
}

function salt(password: string) {
  return "mnemonic" + (unorm.nfkd(password) || ""); // Use unorm until String.prototype.normalize gets better browser support
}

//=========== helper methods from bitcoinjs-lib ========

function bytesToBinary(bytes: any) {
  return bytes
    .map(function (x: any) {
      return lpad(x.toString(2), "0", 8);
    })
    .join("");
}

function lpad(str: string, padString: string, length: number) {
  while (str.length < length) str = padString + str;
  return str;
}

module.exports = {
  mnemonicToSeed: mnemonicToSeed,
  mnemonicToSeedHex: mnemonicToSeedHex,
  mnemonicToEntropy: mnemonicToEntropy,
  entropyToMnemonic: entropyToMnemonic,
  generateMnemonic: generateMnemonic,
  validateMnemonic: validateMnemonic,
  wordlists: {
    EN: DEFAULT_WORDLIST,
    ES: SPANISH_WORDLIST,
  },
};
