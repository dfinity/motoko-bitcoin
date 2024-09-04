import Iter "mo:base/Iter";
import Base58Check "../src/Base58Check";
import {test} "mo:test";

  let testData: [(?[Nat8], Text)] = [
    (
      ?[],
      "3QJmnh"
    ),
    (
      ?[0x61],
      "C2dGTwc"
    ),
    (
      // wrong checksum, decode returns null
      null,
      "C2dGTwa"
    ),
    (
      ?[0x62, 0x62, 0x62],
      "4jF5uERJAK"
    ),
    (
      ?[0x63, 0x63, 0x63],
      "4mT4krqUYJ"
    ),
    (
      ?[
        0x73, 0x69, 0x6d, 0x70, 0x6c, 0x79, 0x20, 0x61, 0x20, 0x6c, 0x6f, 0x6e,
        0x67, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67
      ],
      "BXF1HuEUCqeVzZdrKeJjG74rjeXxqJ7dW"
    ),
    (
      ?[
        0x0, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60, 0x92, 0x58, 0x86, 0xb6,
        0x7d, 0x6, 0x52, 0x99, 0x92, 0x59, 0x15, 0xae, 0xb1, 0x72, 0xc0, 0x66,
        0x47
      ],
      "13REmUhe2ckUKy1FvM7AMCdtyYq831yxM3QeyEu4"
    ),
    (
      ?[
        0x51, 0x6b, 0x6f, 0xcd, 0xf
      ],
      "237LSrY9NUUas"
    ),
    (
      ?[
        0xbf, 0x4f, 0x89, 0x0, 0x1e, 0x67, 0x2, 0x74, 0xdd
      ],
      "GwDDDeduj1jpykc27e"
    ),
    (
      ?[
        0xec, 0xac, 0x89, 0xca, 0xd9, 0x39, 0x23, 0xc0, 0x23, 0x21
      ],
      "2W1Yd5Zu6WGyKVtHGMrH"
    ),
    (
      ?[
       0x10, 0xc8, 0x51, 0x1e
      ],
      "3op3iuGMmhs"
    ),
    (
      ?[
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
      ],
      "111111111146Momb"
    ),
    (
      ?[
        0x0, 0x1, 0x11, 0xd3, 0x8e, 0x5f, 0xc9, 0x7, 0x1f, 0xfc,
        0xd2, 0xb, 0x4a, 0x76, 0x3c, 0xc9, 0xae, 0x4f, 0x25, 0x2b,
        0xb4, 0xe4, 0x8f, 0xd6, 0x6a, 0x83, 0x5e, 0x25, 0x2a, 0xda,
        0x93, 0xff, 0x48, 0xd, 0x6d, 0xd4, 0x3d, 0xc6, 0x2a, 0x64,
        0x11, 0x55, 0xa5
      ],
      "17mxz9b2TuLnDf6XyQrHjAc3UvMoEg7YzRsJkBd4VwNpFh8a1StKmCe5WtAW27Y"
    ),
    (
      null,
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL"
    ),
    (
      ?[
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
        0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
        0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
        0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
        0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
        0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
        0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
        0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
        0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2,
        0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
        0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
        0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
        0xfb, 0xfc, 0xfd, 0xfe, 0xff
      ],
      "151KWPPBRzdWPr1ASeu172gVgLf1YfUp6VJyk6K9t4cLqYtFHcMa2iX8S3NJEprUcW7W5LvaPRpz7UG7puBj5STE3nKhCGt5eckYq7mMn5nT7oTTic2BAX6zDdqrmGCnkszQkzkz8e5QLGDjf7KeQgtEDm4UER6DMSdBjFQVa6cHrrJn9myVyyhUrsVnfUk2WmNFZvkWv3Tnvzo2cJ1xW62XDfUgYz1pd97eUGGPuXvDFfLsBVd1dfdUhPwxW7pMPgdWHTmg5uqKGFF6vE4xXpAqZTbTxRZjCDdTn68c2wrcxApm8hq3JX65Hix7VtcD13FF8b7BzBtwjXq1ze6NMjKgUcqpGV5XA5"
    ),
  ];

test(
  "encode",
  func() {
    for (i in Iter.range(0, testData.size() - 1)) {
      ignore(do ? {
        let input = testData[i].0!;
        let expected = testData[i].1;
        let actual = Base58Check.encode(input);
        assert (expected == actual);
      });
    };
  },
);

test(
  "decode",
  func() {
    for (i in Iter.range(0, testData.size() - 1)) {
      let input = testData[i].1;
      let expected = testData[i].0;
      let actual = Base58Check.decode(input);
      assert (expected == actual);
    };
  },
);
