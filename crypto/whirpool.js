/**whirpoool hash fx attempt
10 rounds
mdconstruction

1. Pad X
2. init hashMatrix XX
2.a split into 512 bit blocks
3. W 10 times

four steps to fx W
1. Subytes, use sbox
2. shift columns
3. mix rows
4. addroundkey/add round constant



*/

const myMessage = "yorule jarule";
const uniMessage = new Secret().encodeMessageUnicode(myMessage);
console.log(uniMessage.length);
class Whirlpool {
  constructor() {
    this.digest = 0;
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
  }

  hash = (message) => {
    plaintext = this.mDPadding(message);
    hashMatrix = this.initHashMatrix(8, 8, 8, 8);
    blocks = this.initBlocks(plaintext);
    blocks.forEach((block, i) => {
      block = 64;
      const hNext = this.W(block, hashMatrix, false);
      const keyNext = this.W(hashMatrix, this.constantSchedule[i], true);
    });
  };

  convertBlockToMatrix = (block = "") => {
    const arr = block.split("");
    return Array.from({ length: 8 }, (_, z) =>
      Array.from({ length: 8 }, (_, y) =>
        Array.from({ length: 8 }, (_, x) => arr[z * 64 + y * 8 + x])
      )
    );
  };

  initBlocks = (plaintext) => {
    const blocks = [];
    for (let i = 0; i < plaintext.length / 512 - 1; i++) {
      blocks.push(plaintext.substring(i * 512, (i + 1) * 512));
    }
    return blocks;
  };

  W = (CState, key, isKey) => {
    const thing = this.mixRows(this.shiftColumns(this.subBytes(CState)));
    return isKey ? this.addRoundConstant(thing, k) : this.addRoundKey(thing, k);
  };

  initHashMatrix = (x, y, z, n) => {
    return Array(x).fill(Array(y).fill(Array(z).fill(n)));
  };

  nearestOddMultiple = (n = 1, m = 256) => {
    if (n === 0) return m;
    if (n % m == 0 && Math.ceil(n / m) % 2 == 1) {
      return n + 2 * m;
    }
    return (Math.ceil(n / m) + (Math.ceil(n / m) % 2 ? 0 : 1)) * m;
  };

  mDPadding = (m = [12, 24, 65]) => {
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

  subBytes = (m = [""]) => {
    const x = parseInt(m.slice(0, 4).join(""), 2);
    const y = parseInt(m.slice(4, 9).join(""), 2);
    return this.sBoxes.sBox[x][y].toString(2).split("");
  };

  /**
   * i = 1
   *[][][][][][][][]
   *[][][][][][][][]
   *[][][][][][][][]
   *[][][][][][][][]
   *[][][][][][][][]
   *[][][][][][][][]
   *[][][][][][][][]
   *[][][][][][][][]
   *
   * let noni =block[1]
   * let cage = noni.steal(last(i))
   * cage.push(noni)
   *  block[1] = cage
   */
  shiftColumns = (b = [["0"]]) => {
    const block = b.map((row) => [...row]);
    for (let i = 1; i < 8; i++) {
      let col = block[i];
      let section = col.splice(col.length - 1 - i);
      section.push(...col);
      block[i] = section;
    }
    return block;
  };
  mixRows = (m) => {};
  addRoundKey = (m, k) => {};
  addRoundConstant = (m, c) => {};

  //   console.log(blocks);
  //   return digest;
}

const w = new Whirlpool();
const bbb = w.mDPadding(
  s.encodeMessageUnicode(
    "Lorem ipsum dolor sit amet consectetur adipisicing elit. Voluptates corrupti vitae architecto! Maiores quasi pariatur quibusdam consequatur officia libero explicabo sit, facere animi? Ipsum et perspiciatis deserunt enim neque repellendus officiis in. Cumque blanditiis eligendi ex aut laudantium soluta officia temporibus! Possimus aspernatur illo molestiae quas atque neque ea sint! Eos voluptates dicta minima error itaque sit! Saepe libero iusto, eligendi repellat quia corporis! Sit, quo fugit amet eos vel enim perferendis architecto. Sit pariatur minima eum aliquam, debitis magnam, nulla eligendi magni laudantium tempore omnis. Libero repudiandae mollitia alias cum temporibus dolorem. Inventore eaque reiciendis illum quasi quaerat voluptate mollitia odio doloremque molestiae dolore dolores sunt necessitatibus fuga ut, at facere totam doloribus recusandae aliquam enim voluptates? Ducimus possimus praesentium impedit ex quidem vel beatae ratione molestiae, earum maiores blanditiis exercitationem quae inventore culpa sed pariatur laborum voluptatum corrupti recusandae ullam! Saepe voluptatum distinctio voluptatibus aliquid rem cum, dolore nihil facilis laudantium nostrum veniam cupiditate fugiat expedita, placeat dignissimos repellendus magni deleniti. Fugit blanditiis ad laudantium hic quisquam repudiandae ullam tempora aperiam. Nam distinctio aliquid laborum ex dolore unde voluptatum totam facilis repellendus accusantium molestiae nostrum commodi, at tempora. Nisi porro iure odio neque ducimus doloribus amet tempora non tempore quasi, officiis eos ullam molestiae, sapiente cum quod animi cumque suscipit, et laborum. Necessitatibus reiciendis nobis voluptate modi fugit aspernatur neque minima laudantium ipsa rem est ipsum dolore magni nihil vitae, perferendis, ut molestias fuga dicta dolores sed quod beatae? Eos officia nesciunt ipsa, dignissimos accusantium sapiente quis obcaecati eum id libero recusandae, placeat fuga! Nisi non voluptate aut? Eius ex quidem sit animi ut, soluta vitae asperiores optio, doloremque alias magni aperiam sed enim quas dicta praesentium quis, debitis quaerat ducimus veniam possimus doloribus aut nemo. Sunt tempora cupiditate earum dolorum unde, facere a inventore sit distinctio tempore, ex accusantium blanditiis possimus nam quia ab? Illo blanditiis veniam iusto quas ad aperiam adipisci architecto maxime ipsam repudiandae unde ab voluptatum, ullam commodi deleniti eius mollitia est labore possimus molestias tempora nam quidem! Quia reiciendis, iure dolore quis enim corporis modi, blanditiis, est deserunt dolor quod fuga magni ad atque dicta officiis saepe autem ipsam tempora ducimus minus repellendus mollitia culpa minima! Quam nihil, architecto vitae repellat vero, temporibus excepturi reprehenderit officiis voluptas rerum dolore sint autem enim nostrum porro et sit fuga maxime! Qui quod quasi error, repellendus, reiciendis earum in dolore quas consequatur, odit accusamus magnam vitae ad obcaecati! Aliquam, distinctio tenetur! Cum quasi voluptatem corrupti harum cumque soluta animi recusandae corporis, aliquam nulla mollitia ab dolorem dolores eius nisi quo deserunt assumenda nihil consequatur consectetur iste tempore, hic temporibus debitis. Aliquid corrupti quis cum iusto asperiores atque animi aperiam vitae laboriosam deserunt accusamus autem recusandae, ea accusantium nihil perspiciatis libero. Tempora deserunt eius facilis repellat minima soluta sequi, sunt magni assumenda id illum voluptas reiciendis iure nisi facere? Ipsum sunt temporibus explicabo ex consequatur placeat. Magnam soluta, consectetur necessitatibus id aliquid veritatis sint similique quas quos fuga, excepturi sit, neque adipisci accusamus inventore. Tempore dolorum nam unde autem numquam ducimus incidunt, repellat quam voluptate voluptatum nihil aperiam ad a! Hic nam dolorem odit facere temporibus esse quo tempora labore. Doloremque at assumenda dignissimos corrupti. Fugit quibusdam quo enim excepturi laborum iure aspernatur exercitationem placeat, assumenda possimus inventore ullam repellat nemo, quidem voluptatum! Laborum eaque placeat atque saepe adipisci, assumenda vero excepturi possimus quia fugiat maiores quibusdam, quam, rem vel eveniet. Sunt accusantium, esse quos ut totam blanditiis velit, ullam sint aliquid accusamus tenetur nostrum quisquam enim repellendus dolore praesentium quis obcaecati quae consequuntur amet natus iusto inventore id? Laboriosam reiciendis, explicabo asperiores nemo eum itaque dolorum!gg"
  )
);
const cc = w.initBlocks(bbb);
const hm = w.initHashMatrix(8, 8, 8, 8);
const co = w.convertBlockToMatrix(cc[0]);
const col = w.shiftColumns(co.map(c=>[...c]))
