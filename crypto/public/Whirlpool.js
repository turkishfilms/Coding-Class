import Security from "./Security.js";

/**whirpoool hash fx attempt
10 rounds
mdconstruction

1. Pad X
2. init hashMatrix XX
2.a split into 512 bit blocks
3. W 10 times

four steps to fx W
1. Subytes, use sbox XX
2. shift columns XXX easy
3. mix rows
4. addroundkey/add round constant
*/
export default class Whirlpool {
  constructor() {
    this.sBoxes = {
      sBox: [
        [
          0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2,
          0xf5, 0x79, 0x6f, 0x91, 0x52,
        ],
        [
          0x60, 0xbc, 0x0b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7,
          0xc2, 0x2e, 0x4b, 0xfe, 0x57,
        ],
        [
          0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xca, 0x58, 0xc9, 0x29,
          0x0a, 0xb1, 0xa0, 0x6b, 0x85,
        ],
        [
          0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41,
          0x8b, 0xa7, 0x7d, 0x95, 0xc8,
        ],
        [
          0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf,
          0x07, 0xad, 0x5a, 0x83, 0x33,
        ],
        [
          0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xc9, 0xf2, 0xe3, 0x5b,
          0x88, 0x9a, 0x26, 0x32, 0xb0,
        ],
        [
          0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90,
          0x5f, 0x20, 0x68, 0x1a, 0xae,
        ],
        [
          0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3,
          0xec, 0xdb, 0xa1, 0x8d, 0x3d,
        ],
        [
          0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a,
          0x50, 0x45, 0xf3, 0x30, 0xef,
        ],
        [
          0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd,
          0x4d, 0x92, 0x75, 0x06, 0x8a,
        ],
        [
          0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25,
          0x59, 0x84, 0x72, 0x39, 0x4c,
        ],
        [
          0x5e, 0x78, 0x38, 0x8c, 0xc1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c,
          0x1e, 0x43, 0xc7, 0xfc, 0x04,
        ],
        [
          0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce,
          0x11, 0x8f, 0x4e, 0xb7, 0xeb,
        ],
        [
          0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4,
          0x03, 0x56, 0x44, 0x7f, 0xa9,
        ],
        [
          0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6,
          0x46, 0xac, 0x89, 0x14, 0xe1,
        ],
        [
          0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xc0, 0xed, 0xcc, 0x42, 0x98,
          0xa4, 0x28, 0x5c, 0xf8, 0x86,
        ],
      ],
      miniBoxes: {
        eBox: [
          0x1, 0xb, 0x9, 0xc, 0xd, 0x6, 0xf, 0x3, 0xe, 0x8, 0x7, 0x4, 0xa, 0x2,
          0x5, 0x0,
        ],
        eBoxInv: [
          0xf, 0x0, 0xd, 0x7, 0xb, 0xe, 0x5, 0xa, 0x9, 0x2, 0xc, 0x1, 0x3, 0x4,
          0x8, 0x6,
        ],
        rBox: [
          0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5,
          0x1, 0x0,
        ],
      },
    };
    this.transitionMatrix = [
      [1, 1, 4, 1, 8, 5, 2, 9],
      [9, 1, 1, 4, 1, 8, 5, 2],
      [2, 9, 1, 1, 4, 1, 8, 5],
      [5, 2, 9, 1, 1, 4, 1, 8],
      [8, 5, 2, 9, 1, 1, 4, 1],
      [1, 8, 5, 2, 9, 1, 1, 4],
      [4, 1, 8, 5, 2, 9, 1, 1],
      [1, 4, 1, 8, 5, 2, 9, 1],
    ];
  }

  hash = (plaintext_ = [0], translator = new Security()) => {
    const plaintext = translator.encodeMessageUnicode(plaintext_);
    const padded = this.mDPadding(plaintext);
    const blocks = this.initBlocks(padded);
    const hashMatrix = this.initHashMatrix(8, 8, 0);
    console.log("WH hash:padded,blocks =>", padded, blocks);
    for (let i = 0; i < blocks.length; i++) {
      this.oneBlock(blocks[i], hashMatrix, this.sBoxes.sBox);
    }
  };

  ////////////////

  mDPadding = (m = [0]) => {
    //m is your message encoded in ascii/unicode aka an array of decimal number 0- 128
    const message = m
      .map((charCode) => charCode.toString(2).padStart(8, "0"))
      .join("");
    return (
      message +
      1 +
      Array(this.nearestOddMultiple(message.length, 256) - message.length - 1)
        .fill("0")
        .join("") +
      message.length.toString(2).padStart(256, "0")
    );
  };

  initBlocks = (plaintext = "") => {
    const blocks = [];
    for (let i = 0; i < plaintext.length / 512 - 1; i++) {
      blocks.push(
        this.convertBlockToMatrix2(plaintext.substring(i * 512, (i + 1) * 512))
      );
    }

    return blocks;
  };

  convertBlockToMatrix2 = (block = "") => {
    const a = block.split("");
    const bs = [];
    for (let i = 0; i < a.length; i += 8) {
      bs.push(parseInt(a.slice(i, i + 8).join(""), 2));
    }
    const mt = [];
    for (let i = 0; i < bs.length; i += 8) {
      mt.push(bs.slice(i, i + 8));
    }
    return mt;
  };

  convertBlockToMatrix = (block = "") => {
    const arr = block.split("");
    return Array.from({ length: 8 }, (_, z) =>
      Array.from({ length: 8 }, (_, y) =>
        Array.from({ length: 8 }, (_, x) => arr[z * 64 + y * 8 + x])
      )
    );
  };

  initHashMatrix = (x, y, n) => {
    return Array(x).fill(Array(y).fill(n));
  };

  oneBlock = (block, key, rcs) => {
    const message = block.map((row) => [...row]);
    const hashKey = key.map((row) => [...row]);
    const roundConstantSchedule = rcs.map((row) => [...row]);

    let h = hashKey;
    let m = this.startup(message, h);
    for (let i = 0; i < 10; i++) {
      console.log("WH oneBlock: roundCount, message, hashkey", i, m, h);
      let roundConstant = [
        roundConstantSchedule[i].map((hexNum) => parseInt(hexNum, 16)),
        ...Array(7).fill(0),
      ];
      console.log("WH oneBlock: roundCConstant =>", roundConstant);
      let { wMessage, wHashKey } = this.round(m, h, roundConstant);
      h = wHashKey;
      m = wMessage;
    }
    return m ^ hashKey ^ block;
  };

  startup = (b, k) => {
    return this.addRoundKey(b, k);
  };

  round = (block, key, roundConstant) => {
    const message = block.map((row) => [...row]);
    const hashKey = key.map((row) => [...row]);

    const wHashKey = this.W(hashKey, roundConstant);
    const wMessage = this.W(message, wHashKey);

    return { wMessage, wHashKey };
  };

  W = (CState, key) => {
    const thing = this.mixRows(
      this.shiftColumns(this.subBytes(CState, this.sBoxes.sBox))
    );
    return this.addRoundKey(thing, key);
  };

  //////
  nearestOddMultiple = (n = 1, m = 256) => {
    if (n === 0) return m;
    if (n % m == 0 && Math.ceil(n / m) % 2 == 1) {
      return n + 2 * m;
    }
    return (Math.ceil(n / m) + (Math.ceil(n / m) % 2 ? 0 : 1)) * m;
  };

  subByte = (m = [2], sbox) => {
    console.log("WH sB:m,=>", m);
    return sbox[m >> 4][parseInt(m.toString(2).slice(-4), 2)];
  };

  subBytes = (block, sBox) => {
    return Array.from({ length: 8 }, (_, x) => {
      return Array.from({ length: 8 }, (_, y) =>
        this.subByte(block[x][y], sBox)
      );
    });
  };

  subByteB = (m = [""], sBox) => {
    const x = parseInt(m.slice(0, 4).join(""), 2);
    const y = parseInt(m.slice(4, 9).join(""), 2);
    return sBox[x][y].toString(2).split("");
  };

  shiftColumns = (b = [["0"]]) => {
    const block = b.map((row) => [...row]);
    for (let i = 1; i < 8; i++) {
      let col = block[i];
      let section = col.splice(col.length - i);
      section.push(...col);
      block[i] = section;
    }
    return block;
  };

  mixRows = (block = [["0"]], transitionMatrix = [[1]]) => {
    return this.gptMR(block, transitionMatrix);
    // return block.map((row, x) => [
    //   ...row.map((col, y) => [
    //     ...col.map((cell, z) => {
    //       return block[x][y];
    //     }),
    //   ]),
    // ]);
  };

  gptMIG = (element1, element2, poly) => {
    // Function to multiply two elements in GF(2^8)
    let result = 0;
    let carry = 0;

    for (let i = 0; i < 8; i++) {
      if (element2 & (1 << i)) {
        result ^= element1;
      }
      carry = element1 & 0x80;
      element1 <<= 1;
      if (carry) {
        element1 ^= poly;
      }
    }
    return result;
  };

  gptMR = (matrixA, matrixB) => {
    const irreduciblePoly = 0b100011011; // The polynomial x^8 + x^4 + x^3 + x^2 + 1
    // Function to perform matrix multiplication in GF(2^8)
    const result = [];
    for (let i = 0; i < matrixA.length; i++) {
      const row = [];
      for (let j = 0; j < matrixB[0].length; j++) {
        let sum = 0;
        for (let k = 0; k < matrixB.length; k++) {
          sum ^= this.gptMIG(matrixA[i][k], matrixB[k][j], irreduciblePoly);
        }
        row.push(sum);
      }
      result.push(row);
    }
    return result;
  };

  addRoundKey = (block, key) => {
    return Array.from({ length: 8 }, (_, x) => {
      return Array.from({ length: 8 }, (_, y) => block[x][y] ^ key[x][y]);
    });
  };

  //   console.log(blocks);
  //   return digest;
}
