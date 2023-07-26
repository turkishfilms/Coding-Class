class Secret {
  constructor() {}
  encryptMessage = (message, key) => {
    return message.map((uniChar, index) => uniChar + key[index]);
  };

  decryptMessage = (encryptedMessage, key) => {
    return encryptedMessage.map((char, index) => char - key[index]);
  };

  encodeMessageUnicode = (message) => {
    return message.split("").map((char) => char.charCodeAt());
  };

  decodeMessageUnicode = (uniCode) => {
    return uniCode.map((char) => String.fromCharCode(char)).join("");
  };

  generateKey = (length, range) => {
    return Array(length)
      .fill(1)
      .map(() => Math.ceil(Math.random() * range));
  };

  symmetricKeyCryptography = (str, key) => {
    return this.decodeMessageUnicode(
      this.decryptMessage(
        this.encryptMessage(this.encodeMessageUnicode(str), key),
        key
      )
    );
  };
}
////// unicode 31 to 127

const nearestOddMultiple = (n = 1, m = 256) => {
  if (n === 0) return m;
  if (n % m == 0 && Math.ceil(n / m) % 2 == 1) {
    return n + 512;
  }
  return (Math.ceil(n / m) + (Math.ceil(n / m) % 2 ? 0 : 1)) * m;
};

const mDPadding = (m = [12, 24, 65]) => {
  //m is your message encoded in ascii/unicode aka an array of decimal number 0- 128
  const message = m
    .map((charCode) => charCode.toString(2).padStart(8, "0"))
    .join("");
  return (
    message +
    1 +
    Array(nearestOddMultiple(message.length, 256) - message.length - 1)
      .fill("0")
      .join("") +
    message.length.toString(2).padStart(256, "0")
  );
};
const s = new Secret();
const m = "you will never get away with this";
const um = s.encodeMessageUnicode(m);
const pm = mDPadding(um);
console.log("p2:pm.length,pml%512 => ", pm.length, pm.length % 512);

const doItAllForMe = (m) => {
  return mDPadding(s.encodeMessageUnicode(m));
};
