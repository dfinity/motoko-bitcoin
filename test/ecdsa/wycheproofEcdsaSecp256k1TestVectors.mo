module {
  public type WycheproofEcdsaTestCase = {
    tcId : Nat;
    comment : Text;
    key : Text;
    msg : Text;
    sig : Text;
    result : Text;
    flags : [Text];
  };

  public let testVectors : [WycheproofEcdsaTestCase] = [
    {
      tcId = 1;
      comment = "signature malleability";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87";
      result = "valid";
      flags = [];
    },
    {
      tcId = 2;
      comment = "Legacy:ASN encoding of r misses leading 0";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30440220813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "acceptable";
      flags = ["MissingZero"];
    },
    {
      tcId = 3;
      comment = "valid";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "valid";
      flags = [];
    },
    {
      tcId = 4;
      comment = "long form encoding of length of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "308145022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 5;
      comment = "length of sequence contains leading 0";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30820045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 6;
      comment = "wrong length of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 7;
      comment = "wrong length of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3044022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 8;
      comment = "uint32 overflow in length of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30850100000045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 9;
      comment = "uint64 overflow in length of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3089010000000000000045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 10;
      comment = "length of sequence = 2**31 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30847fffffff022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 11;
      comment = "length of sequence = 2**32 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3084ffffffff022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 12;
      comment = "length of sequence = 2**40 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3085ffffffffff022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 13;
      comment = "length of sequence = 2**64 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3088ffffffffffffffff022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 14;
      comment = "incorrect length of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30ff022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 15;
      comment = "indefinite length without termination";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3080022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 16;
      comment = "indefinite length without termination";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045028000813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 17;
      comment = "indefinite length without termination";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502806ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 18;
      comment = "removing sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 19;
      comment = "lonely sequence tag";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 20;
      comment = "appending 0's to sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 21;
      comment = "prepending 0's to sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30470000022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 22;
      comment = "appending unused 0's to sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 23;
      comment = "appending null value to sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0500";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 24;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304a4981773045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 25;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304925003045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 26;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30473045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0004deadbeef";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 27;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304a2226498177022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 28;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304922252500022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 29;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304d2223022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650004deadbeef02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 30;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304a022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365222549817702206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 31;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3049022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323652224250002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 32;
      comment = "including garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304d022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365222202206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0004deadbeef";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 33;
      comment = "including undefined tags";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304daa00bb00cd003045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 34;
      comment = "including undefined tags";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304baa02aabb3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 35;
      comment = "including undefined tags";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304d2229aa00bb00cd00022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 36;
      comment = "including undefined tags";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304b2227aa02aabb022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 37;
      comment = "including undefined tags";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304d022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323652228aa00bb00cd0002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 38;
      comment = "including undefined tags";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304b022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323652226aa02aabb02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 39;
      comment = "truncated length of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3081";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 40;
      comment = "using composition with indefinite length";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30803045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 41;
      comment = "using composition with indefinite length";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30492280022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365000002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 42;
      comment = "using composition with indefinite length";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3049022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365228002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 43;
      comment = "using composition with wrong tag";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30803145022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 44;
      comment = "using composition with wrong tag";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30492280032100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365000002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 45;
      comment = "using composition with wrong tag";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3049022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365228003206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 46;
      comment = "Replacing sequence with NULL";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "0500";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 47;
      comment = "changing tag value of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "2e45022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 48;
      comment = "changing tag value of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "2f45022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 49;
      comment = "changing tag value of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3145022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 50;
      comment = "changing tag value of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3245022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 51;
      comment = "changing tag value of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "ff45022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 52;
      comment = "dropping value of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 53;
      comment = "using composition for sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304930010230442100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 54;
      comment = "truncated sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3044022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 55;
      comment = "truncated sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30442100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 56;
      comment = "indefinite length";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3080022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 57;
      comment = "indefinite length with truncated delimiter";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3080022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba00";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 58;
      comment = "indefinite length with additional element";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3080022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba05000000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 59;
      comment = "indefinite length with truncated element";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3080022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba060811220000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 60;
      comment = "indefinite length with garbage";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3080022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000fe02beef";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 61;
      comment = "indefinite length with nonempty EOC";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3080022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0002beef";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 62;
      comment = "prepend empty sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30473000022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 63;
      comment = "append empty sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba3000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 64;
      comment = "append garbage with high tag number";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3048022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31babf7f00";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 65;
      comment = "sequence of sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30473045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 66;
      comment = "truncated sequence: removed last 1 elements";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3023022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 67;
      comment = "repeating element in sequence";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3067022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 68;
      comment = "long form encoding of length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304602812100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 69;
      comment = "long form encoding of length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650281206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 70;
      comment = "length of integer contains leading 0";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30470282002100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 71;
      comment = "length of integer contains leading 0";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365028200206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 72;
      comment = "wrong length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022200813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 73;
      comment = "wrong length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022000813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 74;
      comment = "wrong length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502216ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 75;
      comment = "wrong length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365021f6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 76;
      comment = "uint32 overflow in length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304a0285010000002100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 77;
      comment = "uint32 overflow in length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304a022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365028501000000206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 78;
      comment = "uint64 overflow in length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304e028901000000000000002100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 79;
      comment = "uint64 overflow in length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304e022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502890100000000000000206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 80;
      comment = "length of integer = 2**31 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304902847fffffff00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 81;
      comment = "length of integer = 2**31 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3049022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502847fffffff6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 82;
      comment = "length of integer = 2**32 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30490284ffffffff00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 83;
      comment = "length of integer = 2**32 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3049022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650284ffffffff6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 84;
      comment = "length of integer = 2**40 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304a0285ffffffffff00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 85;
      comment = "length of integer = 2**40 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304a022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650285ffffffffff6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 86;
      comment = "length of integer = 2**64 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304d0288ffffffffffffffff00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 87;
      comment = "length of integer = 2**64 - 1";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304d022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650288ffffffffffffffff6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 88;
      comment = "incorrect length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304502ff00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 89;
      comment = "incorrect length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502ff6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 90;
      comment = "removing integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "302202206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 91;
      comment = "lonely integer tag";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30230202206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 92;
      comment = "lonely integer tag";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3024022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 93;
      comment = "appending 0's to integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022300813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365000002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 94;
      comment = "appending 0's to integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502226ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 95;
      comment = "prepending 0's to integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30470223000000813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 96;
      comment = "prepending 0's to integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022200006ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = ["BER"];
    },
    {
      tcId = 97;
      comment = "appending unused 0's to integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365000002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 98;
      comment = "appending null value to integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022300813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365050002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 99;
      comment = "appending null value to integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502226ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0500";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 100;
      comment = "truncated length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3024028102206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 101;
      comment = "truncated length of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3025022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650281";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 102;
      comment = "Replacing integer with NULL";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3024050002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 103;
      comment = "Replacing integer with NULL";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3025022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650500";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 104;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045002100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 105;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045012100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 106;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045032100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 107;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045042100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 108;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045ff2100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 109;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236500206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 110;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236501206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 111;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236503206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 112;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236504206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 113;
      comment = "changing tag value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365ff206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 114;
      comment = "dropping value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3024020002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 115;
      comment = "dropping value of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3025022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650200";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 116;
      comment = "using composition for integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304922250201000220813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 117;
      comment = "using composition for integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3049022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365222402016f021ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 118;
      comment = "modify first byte of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022102813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 119;
      comment = "modify first byte of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206df18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 120;
      comment = "modify last byte of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323e502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 121;
      comment = "modify last byte of integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb313a";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 122;
      comment = "truncated integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3044022000813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832302206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 123;
      comment = "truncated integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3044022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365021f6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 124;
      comment = "truncated integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3044022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365021ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 125;
      comment = "leading ff in integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30460222ff00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 126;
      comment = "leading ff in integer";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650221ff6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 127;
      comment = "replaced integer by infinity";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "302509018002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 128;
      comment = "replaced integer by infinity";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365090180";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 129;
      comment = "replacing integer with zero";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "302502010002206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 130;
      comment = "replacing integer with zero";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365020100";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 131;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022101813ef79ccefa9a56f7ba805f0e478583b90deabca4b05c4574e49b5899b964a602206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 132;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30440220813ef79ccefa9a56f7ba805f0e47858643b030ef461f1bcdf53fde3ef94ce22402206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 133;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30450221ff7ec10863310565a908457fa0f1b87a7b01a0f22a0a9843f64aedc334367cdc9b02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 134;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304402207ec10863310565a908457fa0f1b87a79bc4fcf10b9e0e4320ac021c106b31ddc02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 135;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30450221fe7ec10863310565a908457fa0f1b87a7c46f215435b4fa3ba8b1b64a766469b5a02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 136;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022101813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 137;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "304402207ec10863310565a908457fa0f1b87a7b01a0f22a0a9843f64aedc334367cdc9b02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 138;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650221016ff18a52dcc0336f7af62400a6dd9b7fc1e197d8aebe203c96c87232272172fb";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 139;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650221ff6ff18a52dcc0336f7af62400a6dd9b824c83de0b502cdfc51723b51886b4f079";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 140;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650220900e75ad233fcc908509dbff5922647ef8cd450e008a7fff2909ec5aa914ce46";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 141;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650221fe900e75ad233fcc908509dbff592264803e1e68275141dfc369378dcdd8de8d05";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 142;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323650221016ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 143;
      comment = "Modified r or s, e.g. by adding or subtracting the order of the group";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647ef8cd450e008a7fff2909ec5aa914ce46";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 144;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3006020100020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 145;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3006020100020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 146;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30060201000201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 147;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020100022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 148;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020100022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 149;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020100022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 150;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020100022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 151;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020100022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 152;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3008020100090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 153;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3006020100090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 154;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3006020101020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 155;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3006020101020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 156;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30060201010201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 157;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 158;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 159;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 160;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 161;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026020101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 162;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3008020101090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 163;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3006020101090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 164;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30060201ff020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 165;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30060201ff020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 166;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30060201ff0201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 167;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30260201ff022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 168;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30260201ff022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 169;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30260201ff022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 170;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30260201ff022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 171;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30260201ff022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 172;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30080201ff090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 173;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30060201ff090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 174;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 175;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 176;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641410201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 177;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 178;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 179;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 180;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 181;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 182;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3028022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 183;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 184;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 185;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 186;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641400201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 187;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 188;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 189;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 190;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 191;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 192;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3028022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 193;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 194;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 195;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 196;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641420201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 197;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 198;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 199;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 200;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 201;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 202;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3028022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 203;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 204;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 205;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 206;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 207;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 208;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 209;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 210;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 211;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 212;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3028022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 213;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 214;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30020100";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 215;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30020101";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 216;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc300201ff";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 217;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 218;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 219;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 220;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 221;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 222;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3028022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30090380fe01";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 223;
      comment = "Signature with special case values for r and s";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30090142";
      result = "invalid";
      flags = ["EdgeCase"];
    },
    {
      tcId = 224;
      comment = "Signature encoding contains wrong types.";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30060201010c0130";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 225;
      comment = "Signature encoding contains wrong types.";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30050201010c00";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 226;
      comment = "Signature encoding contains wrong types.";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30090c0225730c03732573";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 227;
      comment = "Signature encoding contains wrong types.";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "30080201013003020100";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 228;
      comment = "Signature encoding contains wrong types.";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3003020101";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 229;
      comment = "Signature encoding contains wrong types.";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313233343030";
      sig = "3006020101010100";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 230;
      comment = "Edge case for Shamir multiplication";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3235353835";
      sig = "3045022100dd1b7d09a7bd8218961034a39a87fecf5314f00c4d25eb58a07ac85e85eab516022035138c401ef8d3493d65c9002fe62b43aee568731b744548358996d9cc427e06";
      result = "valid";
      flags = [];
    },
    {
      tcId = 231;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "343236343739373234";
      sig = "304502210095c29267d972a043d955224546222bba343fc1d4db0fec262a33ac61305696ae02206edfe96713aed56f8a28a6653f57e0b829712e5eddc67f34682b24f0676b2640";
      result = "valid";
      flags = [];
    },
    {
      tcId = 232;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "37313338363834383931";
      sig = "3045022028f94a894e92024699e345fe66971e3edcd050023386135ab3939d550898fb25022100cd69c1a42be05a6ee1270c821479251e134c21858d800bda6f4e98b37196238e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 233;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3130333539333331363638";
      sig = "3046022100be26b18f9549f89f411a9b52536b15aa270b84548d0e859a1952a27af1a77ac60221008f3e2b05632fc33715572af9124681113f2b84325b80154c044a544dc1a8fa12";
      result = "valid";
      flags = [];
    },
    {
      tcId = 234;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33393439343031323135";
      sig = "3046022100b1a4b1478e65cc3eafdf225d1298b43f2da19e4bcff7eacc0a2e98cd4b74b114022100e8655ce1cfb33ebd30af8ce8e8ae4d6f7b50cd3e22af51bf69e0a2851760d52b";
      result = "valid";
      flags = [];
    },
    {
      tcId = 235;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31333434323933303739";
      sig = "30440220325332021261f1bd18f2712aa1e2252da23796da8a4b1ff6ea18cafec7e171f2022040b4f5e287ee61fc3c804186982360891eaa35c75f05a43ecd48b35d984a6648";
      result = "valid";
      flags = [];
    },
    {
      tcId = 236;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33373036323131373132";
      sig = "3046022100a23ad18d8fc66d81af0903890cbd453a554cb04cdc1a8ca7f7f78e5367ed88a0022100dc1c14d31e3fb158b73c764268c8b55579734a7e2a2c9b5ee5d9d0144ef652eb";
      result = "valid";
      flags = [];
    },
    {
      tcId = 237;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "333433363838373132";
      sig = "304502202bdea41cda63a2d14bf47353bd20880a690901de7cd6e3cc6d8ed5ba0cdb1091022100c31599433036064073835b1e3eba8335a650c8fd786f94fe235ad7d41dc94c7a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 238;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31333531353330333730";
      sig = "3046022100d7cd76ec01c1b1079eba9e2aa2a397243c4758c98a1ba0b7404a340b9b00ced6022100ca8affe1e626dd192174c2937b15bc48f77b5bdfe01f073a8aeaf7f24dc6c85b";
      result = "valid";
      flags = [];
    },
    {
      tcId = 239;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "36353533323033313236";
      sig = "3045022100a872c744d936db21a10c361dd5c9063355f84902219652f6fc56dc95a7139d960220400df7575d9756210e9ccc77162c6b593c7746cfb48ac263c42750b421ef4bb9";
      result = "valid";
      flags = [];
    },
    {
      tcId = 240;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31353634333436363033";
      sig = "30460221009fa9afe07752da10b36d3afcd0fe44bfc40244d75203599cf8f5047fa3453854022100af1f583fec4040ae7e68c968d2bb4b494eec3a33edc7c0ccf95f7f75bc2569c7";
      result = "valid";
      flags = [];
    },
    {
      tcId = 241;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "34343239353339313137";
      sig = "3045022100885640384d0d910efb177b46be6c3dc5cac81f0b88c3190bb6b5f99c2641f2050220738ed9bff116306d9caa0f8fc608be243e0b567779d8dab03e8e19d553f1dc8e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 242;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3130393533323631333531";
      sig = "304502202d051f91c5a9d440c5676985710483bc4f1a6c611b10c95a2ff0363d90c2a45802210092206b19045a41a797cc2f3ac30de9518165e96d5b86341ecb3bcff231b3fd65";
      result = "valid";
      flags = [];
    },
    {
      tcId = 243;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "35393837333530303431";
      sig = "3045022100f3ac2523967482f53d508522712d583f4379cd824101ff635ea0935117baa54f022027f10812227397e02cea96fb0e680761636dab2b080d1fc5d11685cbe8500cfe";
      result = "valid";
      flags = [];
    },
    {
      tcId = 244;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33343633303036383738";
      sig = "304602210096447cf68c3ab7266ed7447de3ac52fed7cc08cbdfea391c18a9b8ab370bc913022100f0a1878b2c53f16e70fe377a5e9c6e86f18ae480a22bb499f5b32e7109c07385";
      result = "valid";
      flags = [];
    },
    {
      tcId = 245;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "39383137333230323837";
      sig = "30450220530a0832b691da0b5619a0b11de6877f3c0971baaa68ed122758c29caaf46b7202210093761bb0a14ccf9f15b4b9ce73c6ec700bd015b8cb1cfac56837f4463f53074e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 246;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33323232303431303436";
      sig = "30460221009c54c25500bde0b92d72d6ec483dc2482f3654294ca74de796b681255ed58a77022100988bac394a90ad89ce360984c0c149dcbd2684bb64498ace90bcf6b6af1c170e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 247;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "36363636333037313034";
      sig = "3045022100e7909d41439e2f6af29136c7348ca2641a2b070d5b64f91ea9da7070c7a2618b022042d782f132fa1d36c2c88ba27c3d678d80184a5d1eccac7501f0b47e3d205008";
      result = "valid";
      flags = [];
    },
    {
      tcId = 248;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31303335393531383938";
      sig = "304502205924873209593135a4c3da7bb381227f8a4b6aa9f34fe5bb7f8fbc131a039ffe022100e0e44ee4bbe370155bf0bbdec265bf9fe31c0746faab446de62e3631eacd111f";
      result = "valid";
      flags = [];
    },
    {
      tcId = 249;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31383436353937313935";
      sig = "3045022100eeb692c9b262969b231c38b5a7f60649e0c875cd64df88f33aa571fa3d29ab0e0220218b3a1eb06379c2c18cf51b06430786d1c64cd2d24c9b232b23e5bac7989acd";
      result = "valid";
      flags = [];
    },
    {
      tcId = 250;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33313336303436313839";
      sig = "3045022100a40034177f36091c2b653684a0e3eb5d4bff18e4d09f664c2800e7cafda1daf802203a3ec29853704e52031c58927a800a968353adc3d973beba9172cbbeab4dd149";
      result = "valid";
      flags = [];
    },
    {
      tcId = 251;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "32363633373834323534";
      sig = "3046022100b5d795cc75cea5c434fa4185180cd6bd21223f3d5a86da6670d71d95680dadbf022100ab1b277ef5ffe134460835e3d1402461ba104cb50b16f397fdc7a9abfefef280";
      result = "valid";
      flags = [];
    },
    {
      tcId = 252;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31363532313030353234";
      sig = "3044022007dc2478d43c1232a4595608c64426c35510051a631ae6a5a6eb1161e57e42e102204a59ea0fdb72d12165cea3bf1ca86ba97517bd188db3dbd21a5a157850021984";
      result = "valid";
      flags = [];
    },
    {
      tcId = 253;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "35373438303831363936";
      sig = "3046022100ddd20c4a05596ca868b558839fce9f6511ddd83d1ccb53f82e5269d559a01552022100a46e8cb8d626cf6c00ddedc3b5da7e613ac376445ee260743f06f79054c7d42a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 254;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "36333433393133343638";
      sig = "30450221009cde6e0ede0a003f02fda0a01b59facfe5dec063318f279ce2de7a9b1062f7b702202886a5b8c679bdf8224c66f908fd6205492cb70b0068d46ae4f33a4149b12a52";
      result = "valid";
      flags = [];
    },
    {
      tcId = 255;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31353431313033353938";
      sig = "3046022100c5771016d0dd6357143c89f684cd740423502554c0c59aa8c99584f1ff38f609022100ab4bfa0bb88ab99791b9b3ab9c4b02bd2a57ae8dde50b9064063fcf85315cfe5";
      result = "valid";
      flags = [];
    },
    {
      tcId = 256;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3130343738353830313238";
      sig = "3045022100a24ebc0ec224bd67ae397cbe6fa37b3125adbd34891abe2d7c7356921916dfe6022034f6eb6374731bbbafc4924fb8b0bdcdda49456d724cdae6178d87014cb53d8c";
      result = "valid";
      flags = [];
    },
    {
      tcId = 257;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3130353336323835353638";
      sig = "304502202557d64a7aee2e0931c012e4fea1cd3a2c334edae68cdeb7158caf21b68e5a2402210080f93244956ffdc568c77d12684f7f004fa92da7e60ae94a1b98c422e23eda34";
      result = "valid";
      flags = [];
    },
    {
      tcId = 258;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "393533393034313035";
      sig = "3046022100c4f2eccbb6a24350c8466450b9d61b207ee359e037b3dcedb42a3f2e6dd6aeb5022100cd9c394a65d0aa322e391eb76b2a1a687f8620a88adef3a01eb8e4fb05b6477a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 259;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "393738383438303339";
      sig = "3046022100eff04781c9cbcd162d0a25a6e2ebcca43506c523385cb515d49ea38a1b12fcad022100ea5328ce6b36e56ab87acb0dcfea498bcec1bba86a065268f6eff3c41c4b0c9c";
      result = "valid";
      flags = [];
    },
    {
      tcId = 260;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33363130363732343432";
      sig = "3046022100f58b4e3110a64bf1b5db97639ee0e5a9c8dfa49dc59b679891f520fdf0584c87022100d32701ae777511624c1f8abbf02b248b04e7a9eb27938f524f3e8828ba40164a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 261;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31303534323430373035";
      sig = "3045022100f8abecaa4f0c502de4bf5903d48417f786bf92e8ad72fec0bd7fcb7800c0bbe302204c7f9e231076a30b7ae36b0cebe69ccef1cd194f7cce93a5588fd6814f437c0e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 262;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "35313734343438313937";
      sig = "304402205d5b38bd37ad498b2227a633268a8cca879a5c7c94a4e416bd0a614d09e606d2022012b8d664ea9991062ecbb834e58400e25c46007af84f6007d7f1685443269afe";
      result = "valid";
      flags = [];
    },
    {
      tcId = 263;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31393637353631323531";
      sig = "304402200c1cd9fe4034f086a2b52d65b9d3834d72aebe7f33dfe8f976da82648177d8e3022013105782e3d0cfe85c2778dec1a848b27ac0ae071aa6da341a9553a946b41e59";
      result = "valid";
      flags = [];
    },
    {
      tcId = 264;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33343437323533333433";
      sig = "3045022100ae7935fb96ff246b7b5d5662870d1ba587b03d6e1360baf47988b5c02ccc1a5b02205f00c323272083782d4a59f2dfd65e49de0693627016900ef7e61428056664b3";
      result = "valid";
      flags = [];
    },
    {
      tcId = 265;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "333638323634333138";
      sig = "3045022000a134b5c6ccbcefd4c882b945baeb4933444172795fa6796aae149067547098022100a991b9efa2db276feae1c115c140770901839d87e60e7ec45a2b81cf3b437be6";
      result = "valid";
      flags = [];
    },
    {
      tcId = 266;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33323631313938363038";
      sig = "304502202e4721363ad3992c139e5a1c26395d2c2d777824aa24fde075e0d7381171309d0221008bf083b6bbe71ecff22baed087d5a77eaeaf726bf14ace2c03fd6e37ba6c26f2";
      result = "valid";
      flags = [];
    },
    {
      tcId = 267;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "39363738373831303934";
      sig = "304502206852e9d3cd9fe373c2d504877967d365ab1456707b6817a042864694e1960ccf022100f9b4d815ebd4cf77847b37952334d05b2045cb398d4c21ba207922a7a4714d84";
      result = "valid";
      flags = [];
    },
    {
      tcId = 268;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "34393538383233383233";
      sig = "30440220188a8c5648dc79eace158cf886c62b5468f05fd95f03a7635c5b4c31f09af4c5022036361a0b571a00c6cd5e686ccbfcfa703c4f97e48938346d0c103fdc76dc5867";
      result = "valid";
      flags = [];
    },
    {
      tcId = 269;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "383234363337383337";
      sig = "3045022100a74f1fb9a8263f62fc4416a5b7d584f4206f3996bb91f6fc8e73b9e92bad0e1302206815032e8c7d76c3ab06a86f33249ce9940148cb36d1f417c2e992e801afa3fa";
      result = "valid";
      flags = [];
    },
    {
      tcId = 270;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3131303230383333373736";
      sig = "3045022007244865b72ff37e62e3146f0dc14682badd7197799135f0b00ade7671742bfe022100f27f3ddc7124b1b58579573a835650e7a8bad5eeb96e9da215cd7bf9a2a039ed";
      result = "valid";
      flags = [];
    },
    {
      tcId = 271;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "313333383731363438";
      sig = "3045022100da7fdd05b5badabd619d805c4ee7d9a84f84ddd5cf9c5bf4d4338140d689ef08022028f1cf4fa1c3c5862cfa149c0013cf5fe6cf5076cae000511063e7de25bb38e5";
      result = "valid";
      flags = [];
    },
    {
      tcId = 272;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "333232313434313632";
      sig = "3046022100d3027c656f6d4fdfd8ede22093e3c303b0133c340d615e7756f6253aea927238022100f6510f9f371b31068d68bfeeaa720eb9bbdc8040145fcf88d4e0b58de0777d2a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 273;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3130363836363535353436";
      sig = "304402200bf6c0188dc9571cd0e21eecac5fbb19d2434988e9cc10244593ef3a98099f6902204864a562661f9221ec88e3dd0bc2f6e27ac128c30cc1a80f79ec670a22b042ee";
      result = "valid";
      flags = [];
    },
    {
      tcId = 274;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "3632313535323436";
      sig = "3045022100ae459640d5d1179be47a47fa538e16d94ddea5585e7a244804a51742c686443a02206c8e30e530a634fae80b3ceb062978b39edbe19777e0a24553b68886181fd897";
      result = "valid";
      flags = [];
    },
    {
      tcId = 275;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "37303330383138373734";
      sig = "304402201cf3517ba3bf2ab8b9ead4ebb6e866cb88a1deacb6a785d3b63b483ca02ac4950220249a798b73606f55f5f1c70de67cb1a0cff95d7dc50b3a617df861bad3c6b1c9";
      result = "valid";
      flags = [];
    },
    {
      tcId = 276;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "35393234353233373434";
      sig = "3045022100e69b5238265ea35d77e4dd172288d8cea19810a10292617d5976519dc5757cb802204b03c5bc47e826bdb27328abd38d3056d77476b2130f3df6ec4891af08ba1e29";
      result = "valid";
      flags = [];
    },
    {
      tcId = 277;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31343935353836363231";
      sig = "304402205f9d7d7c870d085fc1d49fff69e4a275812800d2cf8973e7325866cb40fa2b6f02206d1f5491d9f717a597a15fd540406486d76a44697b3f0d9d6dcef6669f8a0a56";
      result = "valid";
      flags = [];
    },
    {
      tcId = 278;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "34303035333134343036";
      sig = "304402200a7d5b1959f71df9f817146ee49bd5c89b431e7993e2fdecab6858957da685ae02200f8aad2d254690bdc13f34a4fec44a02fd745a422df05ccbb54635a8b86b9609";
      result = "valid";
      flags = [];
    },
    {
      tcId = 279;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "33303936343537353132";
      sig = "3044022079e88bf576b74bc07ca142395fda28f03d3d5e640b0b4ff0752c6d94cd553408022032cea05bd2d706c8f6036a507e2ab7766004f0904e2e5c5862749c0073245d6a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 280;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "32373834303235363230";
      sig = "30450221009d54e037a00212b377bc8874798b8da080564bbdf7e07591b861285809d01488022018b4e557667a82bd95965f0706f81a29243fbdd86968a7ebeb43069db3b18c7f";
      result = "valid";
      flags = [];
    },
    {
      tcId = 281;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "32363138373837343138";
      sig = "304402202664f1ffa982fedbcc7cab1b8bc6e2cb420218d2a6077ad08e591ba9feab33bd022049f5c7cb515e83872a3d41b4cdb85f242ad9d61a5bfc01debfbb52c6c84ba728";
      result = "valid";
      flags = [];
    },
    {
      tcId = 282;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "31363432363235323632";
      sig = "304502205827518344844fd6a7de73cbb0a6befdea7b13d2dee4475317f0f18ffc81524b022100b0a334b1f4b774a5a289f553224d286d239ef8a90929ed2d91423e024eb7fa66";
      result = "valid";
      flags = [];
    },
    {
      tcId = 283;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "36383234313839343336";
      sig = "304602210097ab19bd139cac319325869218b1bce111875d63fb12098a04b0cd59b6fdd3a3022100bce26315c5dbc7b8cfc31425a9b89bccea7aa9477d711a4d377f833dcc28f820";
      result = "valid";
      flags = [];
    },
    {
      tcId = 284;
      comment = "special case hash";
      key = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";
      msg = "343834323435343235";
      sig = "3044022052c683144e44119ae2013749d4964ef67509278f6d38ba869adcfa69970e123d02203479910167408f45bda420a626ec9c4ec711c1274be092198b4187c018b562ca";
      result = "valid";
      flags = [];
    },
    {
      tcId = 285;
      comment = "k*G has a large x-coordinate";
      key = "0407310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc36226a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0";
      msg = "313233343030";
      sig = "30360211014551231950b75fc4402da1722fc9baeb022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 286;
      comment = "r too large";
      key = "0407310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc36226a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 287;
      comment = "r,s are large";
      key = "04bc97e7585eecad48e16683bc4091708e1a930c683fc47001d4b383594f2c4e22705989cf69daeadd4e4e4b8151ed888dfec20fb01728d89d56b3f38f2ae9c8c5";
      msg = "313233343030";
      sig = "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 288;
      comment = "r and s^-1 have a large Hamming weight";
      key = "0444ad339afbc21e9abf7b602a5ca535ea378135b6d10d81310bdd8293d1df3252b63ff7d0774770f8fe1d1722fa83acd02f434e4fc110a0cc8f6dddd37d56c463";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02203e9a7582886089c62fb840cf3b83061cd1cff3ae4341808bb5bdee6191174177";
      result = "valid";
      flags = [];
    },
    {
      tcId = 289;
      comment = "r and s^-1 have a large Hamming weight";
      key = "041260c2122c9e244e1af5151bede0c3ae23b54d7c596881d3eebad21f37dd878c5c9a0c1a9ade76737a8811bd6a7f9287c978ee396aa89c11e47229d2ccb552f0";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022024238e70b431b1a64efdf9032669939d4b77f249503fc6905feb7540dea3e6d2";
      result = "valid";
      flags = [];
    },
    {
      tcId = 290;
      comment = "small r and s";
      key = "041877045be25d34a1d0600f9d5c00d0645a2a54379b6ceefad2e6bf5c2a3352ce821a532cc1751ee1d36d41c3d6ab4e9b143e44ec46d73478ea6a79a5c0e54159";
      msg = "313233343030";
      sig = "3006020101020101";
      result = "valid";
      flags = [];
    },
    {
      tcId = 291;
      comment = "small r and s";
      key = "04455439fcc3d2deeceddeaece60e7bd17304f36ebb602adf5a22e0b8f1db46a50aec38fb2baf221e9a8d1887c7bf6222dd1834634e77263315af6d23609d04f77";
      msg = "313233343030";
      sig = "3006020101020102";
      result = "valid";
      flags = [];
    },
    {
      tcId = 292;
      comment = "small r and s";
      key = "042e1f466b024c0c3ace2437de09127fed04b706f94b19a21bb1c2acf35cece7180449ae3523d72534e964972cfd3b38af0bddd9619e5af223e4d1a40f34cf9f1d";
      msg = "313233343030";
      sig = "3006020101020103";
      result = "valid";
      flags = [];
    },
    {
      tcId = 293;
      comment = "r is larger than n";
      key = "042e1f466b024c0c3ace2437de09127fed04b706f94b19a21bb1c2acf35cece7180449ae3523d72534e964972cfd3b38af0bddd9619e5af223e4d1a40f34cf9f1d";
      msg = "313233343030";
      sig = "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142020103";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 294;
      comment = "s is larger than n";
      key = "04dda95d7b0698de5d2d0b4f0034dbe35b50f978fcc518a84abf9c99efd96a25305adc08d6a63dbe831ab99cd9146e3c4c45492ad19521612542256d6af60e7888";
      msg = "313233343030";
      sig = "3026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd04917c8";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 295;
      comment = "small r and s^-1";
      key = "0402ef4d6d6cfd5a94f1d7784226e3e2a6c0a436c55839619f38fb4472b5f9ee777eb4acd4eebda5cd72875ffd2a2f26229c2dc6b46500919a432c86739f3ae866";
      msg = "313233343030";
      sig = "302702020101022100c58b162c58b162c58b162c58b162c58a1b242973853e16db75c8a1a71da4d39d";
      result = "valid";
      flags = [];
    },
    {
      tcId = 296;
      comment = "smallish r and s^-1";
      key = "04464f4ff715729cae5072ca3bd801d3195b67aec65e9b01aad20a2943dcbcb584b1afd29d31a39a11d570aa1597439b3b2d1971bf2f1abf15432d0207b10d1d08";
      msg = "313233343030";
      sig = "302c02072d9b4d347952cc022100fcbc5103d0da267477d1791461cf2aa44bf9d43198f79507bd8779d69a13108e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 297;
      comment = "100-bit r and small s^-1";
      key = "04157f8fddf373eb5f49cfcf10d8b853cf91cbcd7d665c3522ba7dd738ddb79a4cdeadf1a5c448ea3c9f4191a8999abfcc757ac6d64567ef072c47fec613443b8f";
      msg = "313233343030";
      sig = "3032020d1033e67e37b32b445580bf4efc022100906f906f906f906f906f906f906f906ed8e426f7b1968c35a204236a579723d2";
      result = "valid";
      flags = [];
    },
    {
      tcId = 298;
      comment = "small r and 100 bit s^-1";
      key = "040934a537466c07430e2c48feb990bb19fb78cecc9cee424ea4d130291aa237f0d4f92d23b462804b5b68c52558c01c9996dbf727fccabbeedb9621a400535afa";
      msg = "313233343030";
      sig = "3026020201010220783266e90f43dafe5cd9b3b0be86de22f9de83677d0f50713a468ec72fcf5d57";
      result = "valid";
      flags = [];
    },
    {
      tcId = 299;
      comment = "100-bit r and s^-1";
      key = "04d6ef20be66c893f741a9bf90d9b74675d1c2a31296397acb3ef174fd0b300c654a0c95478ca00399162d7f0f2dc89efdc2b28a30fbabe285857295a4b0c4e265";
      msg = "313233343030";
      sig = "3031020d062522bbd3ecbe7c39e93e7c260220783266e90f43dafe5cd9b3b0be86de22f9de83677d0f50713a468ec72fcf5d57";
      result = "valid";
      flags = [];
    },
    {
      tcId = 300;
      comment = "r and s^-1 are close to n";
      key = "04b7291d1404e0c0c07dab9372189f4bd58d2ceaa8d15ede544d9514545ba9ee0629c9a63d5e308769cc30ec276a410e6464a27eeafd9e599db10f053a4fe4a829";
      msg = "313233343030";
      sig = "3045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03640c1022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0";
      result = "valid";
      flags = [];
    },
    {
      tcId = 301;
      comment = "s == 1";
      key = "04bb79f61857f743bfa1b6e7111ce4094377256969e4e15159123d9548acc3be6c1f9d9f8860dcffd3eb36dd6c31ff2e7226c2009c4c94d8d7d2b5686bf7abd677";
      msg = "313233343030";
      sig = "3025022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1020101";
      result = "valid";
      flags = [];
    },
    {
      tcId = 302;
      comment = "s == 0";
      key = "04bb79f61857f743bfa1b6e7111ce4094377256969e4e15159123d9548acc3be6c1f9d9f8860dcffd3eb36dd6c31ff2e7226c2009c4c94d8d7d2b5686bf7abd677";
      msg = "313233343030";
      sig = "3025022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1020100";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 303;
      comment = "point at infinity during verify";
      key = "04d533b789a4af890fa7a82a1fae58c404f9a62a50b49adafab349c513b415087401b4171b803e76b34a9861e10f7bc289a066fd01bd29f84c987a10a5fb18c2d4";
      msg = "313233343030";
      sig = "304402207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 304;
      comment = "edge case for signature malleability";
      key = "043a3150798c8af69d1e6e981f3a45402ba1d732f4be8330c5164f49e10ec555b4221bd842bc5e4d97eff37165f60e3998a424d72a450cf95ea477c78287d0343a";
      msg = "313233343030";
      sig = "304402207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a002207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
      result = "valid";
      flags = [];
    },
    {
      tcId = 305;
      comment = "edge case for signature malleability";
      key = "043b37df5fb347c69a0f17d85c0c7ca83736883a825e13143d0fcfc8101e851e800de3c090b6ca21ba543517330c04b12f948c6badf14a63abffdf4ef8c7537026";
      msg = "313233343030";
      sig = "304402207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a002207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1";
      result = "valid";
      flags = [];
    },
    {
      tcId = 306;
      comment = "u1 == 1";
      key = "04feb5163b0ece30ff3e03c7d55c4380fa2fa81ee2c0354942ff6f08c99d0cd82ce87de05ee1bda089d3e4e248fa0f721102acfffdf50e654be281433999df897e";
      msg = "313233343030";
      sig = "3045022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215b8022100bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
      result = "valid";
      flags = [];
    },
    {
      tcId = 307;
      comment = "u1 == n - 1";
      key = "04238ced001cf22b8853e02edc89cbeca5050ba7e042a7a77f9382cd414922897640683d3094643840f295890aa4c18aa39b41d77dd0fb3bb2700e4f9ec284ffc2";
      msg = "313233343030";
      sig = "3044022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215b8022044a5ad0bd0636d9e12bc9e0a6bdd5e1bba77f523842193b3b82e448e05d5f11e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 308;
      comment = "u2 == 1";
      key = "04961cf64817c06c0e51b3c2736c922fde18bd8c4906fcd7f5ef66c4678508f35ed2c5d18168cfbe70f2f123bd7419232bb92dd69113e2941061889481c5a027bf";
      msg = "313233343030";
      sig = "3044022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215b8022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215b8";
      result = "valid";
      flags = [];
    },
    {
      tcId = 309;
      comment = "u2 == n - 1";
      key = "0413681eae168cd4ea7cf2e2a45d052742d10a9f64e796867dbdcb829fe0b1028816528760d177376c09df79de39557c329cc1753517acffe8fa2ec298026b8384";
      msg = "313233343030";
      sig = "3045022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215b8022100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9d1c9e899ca306ad27fe1945de0242b89";
      result = "valid";
      flags = [];
    },
    {
      tcId = 310;
      comment = "edge case for u1";
      key = "045aa7abfdb6b4086d543325e5d79c6e95ce42f866d2bb84909633a04bb1aa31c291c80088794905e1da33336d874e2f91ccf45cc59185bede5dd6f3f7acaae18b";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100e91e1ba6ba898620a46bcb51dc0b8b4ad1dc35dad892c4552d1847b2ce444637";
      result = "valid";
      flags = [];
    },
    {
      tcId = 311;
      comment = "edge case for u1";
      key = "0400277791b305a45b2b39590b2f05d3392a6c8182cef4eb540120e0f5c206c3e464108233fb0b8c3ac892d79ef8e0fbf92ed133addb4554270132584dc52eef41";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100e36bf0cec06d9b841da81332812f74f30bbaec9f202319206c6f0b8a0a400ff7";
      result = "valid";
      flags = [];
    },
    {
      tcId = 312;
      comment = "edge case for u1";
      key = "046efa092b68de9460f0bcc919005a5f6e80e19de98968be3cd2c770a9949bfb1ac75e6e5087d6550d5f9beb1e79e5029307bc255235e2d5dc99241ac3ab886c49";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100ea26b57af884b6c06e348efe139c1e4e9ec9518d60c340f6bac7d278ca08d8a6";
      result = "valid";
      flags = [];
    },
    {
      tcId = 313;
      comment = "edge case for u1";
      key = "0472d4a19c4f9d2cf5848ea40445b70d4696b5f02d632c0c654cc7d7eeb0c6d058e8c4cd9943e459174c7ac01fa742198e47e6c19a6bdb0c4f6c237831c1b3f942";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02205b1d27a7694c146244a5ad0bd0636d9d9ef3b9fb58385418d9c982105077d1b7";
      result = "valid";
      flags = [];
    },
    {
      tcId = 314;
      comment = "edge case for u1";
      key = "042a8ea2f50dcced0c217575bdfa7cd47d1c6f100041ec0e35512794c1be7e740258f8c17122ed303fda7143eb58bede70295b653266013b0b0ebd3f053137f6ec";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100d27a7694c146244a5ad0bd0636d9e12abe687897e8e9998ddbd4e59a78520d0f";
      result = "valid";
      flags = [];
    },
    {
      tcId = 315;
      comment = "edge case for u1";
      key = "0488de689ce9af1e94be6a2089c8a8b1253ffdbb6c8e9c86249ba220001a4ad3b80c4998e54842f413b9edb1825acbb6335e81e4d184b2b01c8bebdc85d1f28946";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100a4f4ed29828c4894b5a17a0c6db3c256c2221449228a92dff7d76ca8206dd8dd";
      result = "valid";
      flags = [];
    },
    {
      tcId = 316;
      comment = "edge case for u1";
      key = "04fea2d31f70f90d5fb3e00e186ac42ab3c1615cee714e0b4e1131b3d4d8225bf7b037a18df2ac15343f30f74067ddf29e817d5f77f8dce05714da59c094f0cda9";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0220694c146244a5ad0bd0636d9e12bc9e09e60e68b90d0b5e6c5dddd0cb694d8799";
      result = "valid";
      flags = [];
    },
    {
      tcId = 317;
      comment = "edge case for u1";
      key = "047258911e3d423349166479dbe0b8341af7fbd03d0a7e10edccb36b6ceea5a3db17ac2b8992791128fa3b96dc2fbd4ca3bfa782ef2832fc6656943db18e7346b0";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02203d7f487c07bfc5f30846938a3dcef696444707cf9677254a92b06c63ab867d22";
      result = "valid";
      flags = [];
    },
    {
      tcId = 318;
      comment = "edge case for u1";
      key = "044f28461dea64474d6bb34d1499c97d37b9e95633df1ceeeaacd45016c98b3914c8818810b8cc06ddb40e8a1261c528faa589455d5a6df93b77bc5e0e493c7470";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02206c7648fc0fbf8a06adb8b839f97b4ff7a800f11b1e37c593b261394599792ba4";
      result = "valid";
      flags = [];
    },
    {
      tcId = 319;
      comment = "edge case for u1";
      key = "0474f2a814fb5d8eca91a69b5e60712732b3937de32829be974ed7b68c5c2f5d66eff0f07c56f987a657f42196205f588c0f1d96fd8a63a5f238b48f478788fe3b";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0221009be363a286f23f6322c205449d320baad417953ecb70f6214e90d49d7d1f26a8";
      result = "valid";
      flags = [];
    },
    {
      tcId = 320;
      comment = "edge case for u1";
      key = "04195b51a7cc4a21b8274a70a90de779814c3c8ca358328208c09a29f336b82d6ab2416b7c92fffdc29c3b1282dd2a77a4d04df7f7452047393d849989c5cee9ad";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022029798c5c45bdf58b4a7b2fdc2c46ab4af1218c7eeb9f0f27a88f1267674de3b0";
      result = "valid";
      flags = [];
    },
    {
      tcId = 321;
      comment = "edge case for u1";
      key = "04622fc74732034bec2ddf3bc16d34b3d1f7a327dd2a8c19bab4bb4fe3a24b58aa736b2f2fae76f4dfaecc9096333b01328d51eb3fda9c9227e90d0b449983c4f0";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02200b70f22ca2bb3cefadca1a5711fa3a59f4695385eb5aedf3495d0b6d00f8fd85";
      result = "valid";
      flags = [];
    },
    {
      tcId = 322;
      comment = "edge case for u1";
      key = "041f7f85caf2d7550e7af9b65023ebb4dce3450311692309db269969b834b611c70827f45b78020ecbbaf484fdd5bfaae6870f1184c21581baf6ef82bd7b530f93";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022016e1e459457679df5b9434ae23f474b3e8d2a70bd6b5dbe692ba16da01f1fb0a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 323;
      comment = "edge case for u1";
      key = "0449c197dc80ad1da47a4342b93893e8e1fb0bb94fc33a83e783c00b24c781377aefc20da92bac762951f72474becc734d4cc22ba81b895e282fdac4df7af0f37d";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02202252d685e831b6cf095e4f0535eeaf0ddd3bfa91c210c9d9dc17224702eaf88f";
      result = "valid";
      flags = [];
    },
    {
      tcId = 324;
      comment = "edge case for u1";
      key = "04d8cb68517b616a56400aa3868635e54b6f699598a2f6167757654980baf6acbe7ec8cf449c849aa03461a30efada41453c57c6e6fbc93bbc6fa49ada6dc0555c";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022075135abd7c425b60371a477f09ce0f274f64a8c6b061a07b5d63e93c65046c53";
      result = "valid";
      flags = [];
    },
    {
      tcId = 325;
      comment = "edge case for u2";
      key = "04030713fb63f2aa6fe2cadf1b20efc259c77445dafa87dac398b84065ca347df3b227818de1a39b589cb071d83e5317cccdc2338e51e312fe31d8dc34a4801750";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100d55555555555555555555555555555547c74934474db157d2a8c3f088aced62a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 326;
      comment = "edge case for u2";
      key = "04babb3677b0955802d8e929a41355640eaf1ea1353f8a771331c4946e3480afa7252f196c87ed3d2a59d3b1b559137fed0013fecefc19fb5a92682b9bca51b950";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100c1777c8853938e536213c02464a936000ba1e21c0fc62075d46c624e23b52f31";
      result = "valid";
      flags = [];
    },
    {
      tcId = 327;
      comment = "edge case for u2";
      key = "041aab2018793471111a8a0e9b143fde02fc95920796d3a63de329b424396fba60bbe4130705174792441b318d3aa31dfe8577821e9b446ec573d272e036c4ebe9";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022030bbb794db588363b40679f6c182a50d3ce9679acdd3ffbe36d7813dacbdc818";
      result = "valid";
      flags = [];
    },
    {
      tcId = 328;
      comment = "edge case for u2";
      key = "048cb0b909499c83ea806cd885b1dd467a0119f06a88a0276eb0cfda274535a8ff47b5428833bc3f2c8bf9d9041158cf33718a69961cd01729bc0011d1e586ab75";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02202c37fd995622c4fb7fffffffffffffffc7cee745110cb45ab558ed7c90c15a2f";
      result = "valid";
      flags = [];
    },
    {
      tcId = 329;
      comment = "edge case for u2";
      key = "048f03cf1a42272bb1532723093f72e6feeac85e1700e9fbe9a6a2dd642d74bf5d3b89a7189dad8cf75fc22f6f158aa27f9c2ca00daca785be3358f2bda3862ca0";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02207fd995622c4fb7ffffffffffffffffff5d883ffab5b32652ccdcaa290fccb97d";
      result = "valid";
      flags = [];
    },
    {
      tcId = 330;
      comment = "edge case for u2";
      key = "0444de3b9c7a57a8c9e820952753421e7d987bb3d79f71f013805c897e018f8acea2460758c8f98d3fdce121a943659e372c326fff2e5fc2ae7fa3f79daae13c12";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100ffb32ac4589f6ffffffffffffffffffebb107ff56b664ca599b954521f9972fa";
      result = "valid";
      flags = [];
    },
    {
      tcId = 331;
      comment = "edge case for u2";
      key = "046fb8b2b48e33031268ad6a517484dc8839ea90f6669ea0c7ac3233e2ac31394a0ac8bbe7f73c2ff4df9978727ac1dfc2fd58647d20f31f99105316b64671f204";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02205622c4fb7fffffffffffffffffffffff928a8f1c7ac7bec1808b9f61c01ec327";
      result = "valid";
      flags = [];
    },
    {
      tcId = 332;
      comment = "edge case for u2";
      key = "04bea71122a048693e905ff602b3cf9dd18af69b9fc9d8431d2b1dd26b942c95e6f43c7b8b95eb62082c12db9dbda7fe38e45cbe4a4886907fb81bdb0c5ea9246c";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022044104104104104104104104104104103b87853fd3b7d3f8e175125b4382f25ed";
      result = "valid";
      flags = [];
    },
    {
      tcId = 333;
      comment = "edge case for u2";
      key = "04da918c731ba06a20cb94ef33b778e981a404a305f1941fe33666b45b03353156e2bb2694f575b45183be78e5c9b5210bf3bf488fd4c8294516d89572ca4f5391";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02202739ce739ce739ce739ce739ce739ce705560298d1f2f08dc419ac273a5b54d9";
      result = "valid";
      flags = [];
    },
    {
      tcId = 334;
      comment = "edge case for u2";
      key = "043007e92c3937dade7964dfa35b0eff031f7eb02aed0a0314411106cdeb70fe3d5a7546fc0552997b20e3d6f413e75e2cb66e116322697114b79bac734bfc4dc5";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100b777777777777777777777777777777688e6a1fe808a97a348671222ff16b863";
      result = "valid";
      flags = [];
    },
    {
      tcId = 335;
      comment = "edge case for u2";
      key = "0460e734ef5624d3cbf0ddd375011bd663d6d6aebc644eb599fdf98dbdcd18ce9bd2d90b3ac31f139af832cccf6ccbbb2c6ea11fa97370dc9906da474d7d8a7567";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02206492492492492492492492492492492406dd3a19b8d5fb875235963c593bd2d3";
      result = "valid";
      flags = [];
    },
    {
      tcId = 336;
      comment = "edge case for u2";
      key = "0485a900e97858f693c0b7dfa261e380dad6ea046d1f65ddeeedd5f7d8af0ba33769744d15add4f6c0bc3b0da2aec93b34cb8c65f9340ddf74e7b0009eeeccce3c";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100955555555555555555555555555555547c74934474db157d2a8c3f088aced62c";
      result = "valid";
      flags = [];
    },
    {
      tcId = 337;
      comment = "edge case for u2";
      key = "0438066f75d88efc4c93de36f49e037b234cc18b1de5608750a62cab0345401046a3e84bed8cfcb819ef4d550444f2ce4b651766b69e2e2901f88836ff90034fed";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc02202aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3e3a49a23a6d8abe95461f8445676b17";
      result = "valid";
      flags = [];
    },
    {
      tcId = 338;
      comment = "edge case for u2";
      key = "0498f68177dc95c1b4cbfa5245488ca523a7d5629470d035d621a443c72f39aabfa33d29546fa1c648f2c7d5ccf70cf1ce4ab79b5db1ac059dbecd068dbdff1b89";
      msg = "313233343030";
      sig = "304502207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc022100bffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143";
      result = "valid";
      flags = [];
    },
    {
      tcId = 339;
      comment = "edge case for u2";
      key = "045c2bbfa23c9b9ad07f038aa89b4930bf267d9401e4255de9e8da0a5078ec8277e3e882a31d5e6a379e0793983ccded39b95c4353ab2ff01ea5369ba47b0c3191";
      msg = "313233343030";
      sig = "304402207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0220185ddbca6dac41b1da033cfb60c152869e74b3cd66e9ffdf1b6bc09ed65ee40c";
      result = "valid";
      flags = [];
    },
    {
      tcId = 340;
      comment = "point duplication during verification";
      key = "042ea7133432339c69d27f9b267281bd2ddd5f19d6338d400a05cd3647b157a3853547808298448edb5e701ade84cd5fb1ac9567ba5e8fb68a6b933ec4b5cc84cc";
      msg = "313233343030";
      sig = "3045022032b0d10d8d0e04bc8d4d064d270699e87cffc9b49c5c20730e1c26f6105ddcda022100d612c2984c2afa416aa7f2882a486d4a8426cb6cfc91ed5b737278f9fca8be68";
      result = "valid";
      flags = ["PointDuplication"];
    },
    {
      tcId = 341;
      comment = "duplication bug";
      key = "042ea7133432339c69d27f9b267281bd2ddd5f19d6338d400a05cd3647b157a385cab87f7d67bb7124a18fe5217b32a04e536a9845a1704975946cc13a4a337763";
      msg = "313233343030";
      sig = "3045022032b0d10d8d0e04bc8d4d064d270699e87cffc9b49c5c20730e1c26f6105ddcda022100d612c2984c2afa416aa7f2882a486d4a8426cb6cfc91ed5b737278f9fca8be68";
      result = "invalid";
      flags = ["PointDuplication"];
    },
    {
      tcId = 342;
      comment = "comparison with point at infinity ";
      key = "048aa2c64fa9c6437563abfbcbd00b2048d48c18c152a2a6f49036de7647ebe82e1ce64387995c68a060fa3bc0399b05cc06eec7d598f75041a4917e692b7f51ff";
      msg = "313233343030";
      sig = "3044022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0022033333333333333333333333333333332f222f8faefdb533f265d461c29a47373";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 343;
      comment = "extreme value for k and edgecase s";
      key = "04391427ff7ee78013c14aec7d96a8a062209298a783835e94fd6549d502fff71fdd6624ec343ad9fcf4d9872181e59f842f9ba4cccae09a6c0972fb6ac6b4c6bd";
      msg = "313233343030";
      sig = "3045022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0";
      result = "valid";
      flags = [];
    },
    {
      tcId = 344;
      comment = "extreme value for k and s^-1";
      key = "04e762b8a219b4f180219cc7a9059245e4961bd191c03899789c7a34b89e8c138ec1533ef0419bb7376e0bfde9319d10a06968791d9ea0eed9c1ce6345aed9759e";
      msg = "313233343030";
      sig = "3046022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5022100b6db6db6db6db6db6db6db6db6db6db5f30f30127d33e02aad96438927022e9c";
      result = "valid";
      flags = [];
    },
    {
      tcId = 345;
      comment = "extreme value for k and s^-1";
      key = "049aedb0d281db164e130000c5697fae0f305ef848be6fffb43ac593fbb950e952fa6f633359bdcd82b56b0b9f965b037789d46b9a8141b791b2aefa713f96c175";
      msg = "313233343030";
      sig = "3046022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502210099999999999999999999999999999998d668eaf0cf91f9bd7317d2547ced5a5a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 346;
      comment = "extreme value for k and s^-1";
      key = "048ad445db62816260e4e687fd1884e48b9fc0636d031547d63315e792e19bfaee1de64f99d5f1cd8b6ec9cb0f787a654ae86993ba3db1008ef43cff0684cb22bd";
      msg = "313233343030";
      sig = "3045022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5022066666666666666666666666666666665e445f1f5dfb6a67e4cba8c385348e6e7";
      result = "valid";
      flags = [];
    },
    {
      tcId = 347;
      comment = "extreme value for k and s^-1";
      key = "041f5799c95be89063b24f26e40cb928c1a868a76fb0094607e8043db409c91c32e75724e813a4191e3a839007f08e2e897388b06d4a00de6de60e536d91fab566";
      msg = "313233343030";
      sig = "3045022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5022049249249249249249249249249249248c79facd43214c011123c1b03a93412a5";
      result = "valid";
      flags = [];
    },
    {
      tcId = 348;
      comment = "extreme value for k";
      key = "04a3331a4e1b4223ec2c027edd482c928a14ed358d93f1d4217d39abf69fcb5ccc28d684d2aaabcd6383775caa6239de26d4c6937bb603ecb4196082f4cffd509d";
      msg = "313233343030";
      sig = "3045022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502200eb10e5ab95f2f275348d82ad2e4d7949c8193800d8c9c75df58e343f0ebba7b";
      result = "valid";
      flags = [];
    },
    {
      tcId = 349;
      comment = "extreme value for k and edgecase s";
      key = "043f3952199774c7cf39b38b66cb1042a6260d8680803845e4d433adba3bb248185ea495b68cbc7ed4173ee63c9042dc502625c7eb7e21fb02ca9a9114e0a3a18d";
      msg = "313233343030";
      sig = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0";
      result = "valid";
      flags = [];
    },
    {
      tcId = 350;
      comment = "extreme value for k and s^-1";
      key = "04cdfb8c0f422e144e137c2412c86c171f5fe3fa3f5bbb544e9076288f3ced786e054fd0721b77c11c79beacb3c94211b0a19bda08652efeaf92513a3b0a163698";
      msg = "313233343030";
      sig = "3045022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022100b6db6db6db6db6db6db6db6db6db6db5f30f30127d33e02aad96438927022e9c";
      result = "valid";
      flags = [];
    },
    {
      tcId = 351;
      comment = "extreme value for k and s^-1";
      key = "0473598a6a1c68278fa6bfd0ce4064e68235bc1c0f6b20a928108be336730f87e3cbae612519b5032ecc85aed811271a95fe7939d5d3460140ba318f4d14aba31d";
      msg = "313233343030";
      sig = "3045022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802210099999999999999999999999999999998d668eaf0cf91f9bd7317d2547ced5a5a";
      result = "valid";
      flags = [];
    },
    {
      tcId = 352;
      comment = "extreme value for k and s^-1";
      key = "0458debd9a7ee2c9d59132478a5440ae4d5d7ed437308369f92ea86c82183f10a16773e76f5edbf4da0e4f1bdffac0f57257e1dfa465842931309a24245fda6a5d";
      msg = "313233343030";
      sig = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022066666666666666666666666666666665e445f1f5dfb6a67e4cba8c385348e6e7";
      result = "valid";
      flags = [];
    },
    {
      tcId = 353;
      comment = "extreme value for k and s^-1";
      key = "048b904de47967340c5f8c3572a720924ef7578637feab1949acb241a5a6ac3f5b950904496f9824b1d63f3313bae21b89fae89afdfc811b5ece03fd5aa301864f";
      msg = "313233343030";
      sig = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022049249249249249249249249249249248c79facd43214c011123c1b03a93412a5";
      result = "valid";
      flags = [];
    },
    {
      tcId = 354;
      comment = "extreme value for k";
      key = "04f4892b6d525c771e035f2a252708f3784e48238604b4f94dc56eaa1e546d941a346b1aa0bce68b1c50e5b52f509fb5522e5c25e028bc8f863402edb7bcad8b1b";
      msg = "313233343030";
      sig = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802200eb10e5ab95f2f275348d82ad2e4d7949c8193800d8c9c75df58e343f0ebba7b";
      result = "valid";
      flags = [];
    },
    {
      tcId = 355;
      comment = "testing point duplication";
      key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
      msg = "313233343030";
      sig = "3045022100bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca60502302202492492492492492492492492492492463cfd66a190a6008891e0d81d49a0952";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 356;
      comment = "testing point duplication";
      key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
      msg = "313233343030";
      sig = "3044022044a5ad0bd0636d9e12bc9e0a6bdd5e1bba77f523842193b3b82e448e05d5f11e02202492492492492492492492492492492463cfd66a190a6008891e0d81d49a0952";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 357;
      comment = "testing point duplication";
      key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777";
      msg = "313233343030";
      sig = "3045022100bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca60502302202492492492492492492492492492492463cfd66a190a6008891e0d81d49a0952";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 358;
      comment = "testing point duplication";
      key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777";
      msg = "313233343030";
      sig = "3044022044a5ad0bd0636d9e12bc9e0a6bdd5e1bba77f523842193b3b82e448e05d5f11e02202492492492492492492492492492492463cfd66a190a6008891e0d81d49a0952";
      result = "invalid";
      flags = [];
    },
    {
      tcId = 359;
      comment = "pseudorandom signature";
      key = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152";
      msg = "";
      sig = "3046022100f80ae4f96cdbc9d853f83d47aae225bf407d51c56b7776cd67d0dc195d99a9dc022100b303e26be1f73465315221f0b331528807a1a9b6eb068ede6eebeaaa49af8a36";
      result = "valid";
      flags = [];
    },
    {
      tcId = 360;
      comment = "pseudorandom signature";
      key = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152";
      msg = "4d7367";
      sig = "30450220109cd8ae0374358984a8249c0a843628f2835ffad1df1a9a69aa2fe72355545c022100ac6f00daf53bd8b1e34da329359b6e08019c5b037fed79ee383ae39f85a159c6";
      result = "valid";
      flags = [];
    },
    {
      tcId = 361;
      comment = "pseudorandom signature";
      key = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152";
      msg = "313233343030";
      sig = "3045022100d035ee1f17fdb0b2681b163e33c359932659990af77dca632012b30b27a057b302201939d9f3b2858bc13e3474cb50e6a82be44faa71940f876c1cba4c3e989202b6";
      result = "valid";
      flags = [];
    },
    {
      tcId = 362;
      comment = "pseudorandom signature";
      key = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152";
      msg = "0000000000000000000000000000000000000000";
      sig = "304402204f053f563ad34b74fd8c9934ce59e79c2eb8e6eca0fef5b323ca67d5ac7ed23802204d4b05daa0719e773d8617dce5631c5fd6f59c9bdc748e4b55c970040af01be5";
      result = "valid";
      flags = [];
    },
    {
      tcId = 363;
      comment = "y-coordinate of the public key is small";
      key = "046e823555452914099182c6b2c1d6f0b5d28d50ccd005af2ce1bba541aa40caff00000001060492d5a5673e0f25d8d50fb7e58c49d86d46d4216955e0aa3d40e1";
      msg = "4d657373616765";
      sig = "304402206d6a4f556ccce154e7fb9f19e76c3deca13d59cc2aeb4ecad968aab2ded45965022053b9fa74803ede0fc4441bf683d56c564d3e274e09ccf47390badd1471c05fb7";
      result = "valid";
      flags = [];
    },
    {
      tcId = 364;
      comment = "y-coordinate of the public key is small";
      key = "046e823555452914099182c6b2c1d6f0b5d28d50ccd005af2ce1bba541aa40caff00000001060492d5a5673e0f25d8d50fb7e58c49d86d46d4216955e0aa3d40e1";
      msg = "4d657373616765";
      sig = "3046022100aad503de9b9fd66b948e9acf596f0a0e65e700b28b26ec56e6e45e846489b3c4022100fff223c5d0765447e8447a3f9d31fd0696e89d244422022ff61a110b2a8c2f04";
      result = "valid";
      flags = [];
    },
    {
      tcId = 365;
      comment = "y-coordinate of the public key is small";
      key = "046e823555452914099182c6b2c1d6f0b5d28d50ccd005af2ce1bba541aa40caff00000001060492d5a5673e0f25d8d50fb7e58c49d86d46d4216955e0aa3d40e1";
      msg = "4d657373616765";
      sig = "30460221009182cebd3bb8ab572e167174397209ef4b1d439af3b200cdf003620089e43225022100abb88367d15fe62d1efffb6803da03109ee22e90bc9c78e8b4ed23630b82ea9d";
      result = "valid";
      flags = [];
    },
    {
      tcId = 366;
      comment = "y-coordinate of the public key is large";
      key = "046e823555452914099182c6b2c1d6f0b5d28d50ccd005af2ce1bba541aa40cafffffffffef9fb6d2a5a98c1f0da272af0481a73b62792b92bde96aa1e55c2bb4e";
      msg = "4d657373616765";
      sig = "304502203854a3998aebdf2dbc28adac4181462ccac7873907ab7f212c42db0e69b56ed8022100c12c09475c772fd0c1b2060d5163e42bf71d727e4ae7c03eeba954bf50b43bb3";
      result = "valid";
      flags = [];
    },
    {
      tcId = 367;
      comment = "y-coordinate of the public key is large";
      key = "046e823555452914099182c6b2c1d6f0b5d28d50ccd005af2ce1bba541aa40cafffffffffef9fb6d2a5a98c1f0da272af0481a73b62792b92bde96aa1e55c2bb4e";
      msg = "4d657373616765";
      sig = "3046022100e94dbdc38795fe5c904d8f16d969d3b587f0a25d2de90b6d8c5c53ff887e3607022100856b8c963e9b68dade44750bf97ec4d11b1a0a3804f4cb79aa27bdea78ac14e4";
      result = "valid";
      flags = [];
    },
    {
      tcId = 368;
      comment = "y-coordinate of the public key is large";
      key = "046e823555452914099182c6b2c1d6f0b5d28d50ccd005af2ce1bba541aa40cafffffffffef9fb6d2a5a98c1f0da272af0481a73b62792b92bde96aa1e55c2bb4e";
      msg = "4d657373616765";
      sig = "3044022049fc102a08ca47b60e0858cd0284d22cddd7233f94aaffbb2db1dd2cf08425e102205b16fca5a12cdb39701697ad8e39ffd6bdec0024298afaa2326aea09200b14d6";
      result = "valid";
      flags = [];
    },
    {
      tcId = 369;
      comment = "x-coordinate of the public key is small";
      key = "04000000013fd22248d64d95f73c29b48ab48631850be503fd00f8468b5f0f70e0f6ee7aa43bc2c6fd25b1d8269241cbdd9dbb0dac96dc96231f430705f838717d";
      msg = "4d657373616765";
      sig = "3045022041efa7d3f05a0010675fcb918a45c693da4b348df21a59d6f9cd73e0d831d67a022100bbab52596c1a1d9484296cdc92cbf07e665259a13791a8fe8845e2c07cf3fc67";
      result = "valid";
      flags = [];
    },
    {
      tcId = 370;
      comment = "x-coordinate of the public key is small";
      key = "04000000013fd22248d64d95f73c29b48ab48631850be503fd00f8468b5f0f70e0f6ee7aa43bc2c6fd25b1d8269241cbdd9dbb0dac96dc96231f430705f838717d";
      msg = "4d657373616765";
      sig = "3046022100b615698c358b35920dd883eca625a6c5f7563970cdfc378f8fe0cee17092144c022100da0b84cd94a41e049ef477aeac157b2a9bfa6b7ac8de06ed3858c5eede6ddd6d";
      result = "valid";
      flags = [];
    },
    {
      tcId = 371;
      comment = "x-coordinate of the public key is small";
      key = "04000000013fd22248d64d95f73c29b48ab48631850be503fd00f8468b5f0f70e0f6ee7aa43bc2c6fd25b1d8269241cbdd9dbb0dac96dc96231f430705f838717d";
      msg = "4d657373616765";
      sig = "304602210087cf8c0eb82d44f69c60a2ff5457d3aaa322e7ec61ae5aecfd678ae1c1932b0e022100c522c4eea7eafb82914cbf5c1ff76760109f55ddddcf58274d41c9bc4311e06e";
      result = "valid";
      flags = [];
    },
    {
      tcId = 372;
      comment = "x-coordinate of the public key has many trailing 1's";
      key = "0425afd689acabaed67c1f296de59406f8c550f57146a0b4ec2c97876dfffffffffa46a76e520322dfbc491ec4f0cc197420fc4ea5883d8f6dd53c354bc4f67c35";
      msg = "4d657373616765";
      sig = "3045022062f48ef71ace27bf5a01834de1f7e3f948b9dce1ca1e911d5e13d3b104471d82022100a1570cc0f388768d3ba7df7f212564caa256ff825df997f21f72f5280d53011f";
      result = "valid";
      flags = [];
    },
    {
      tcId = 373;
      comment = "x-coordinate of the public key has many trailing 1's";
      key = "0425afd689acabaed67c1f296de59406f8c550f57146a0b4ec2c97876dfffffffffa46a76e520322dfbc491ec4f0cc197420fc4ea5883d8f6dd53c354bc4f67c35";
      msg = "4d657373616765";
      sig = "3046022100f6b0e2f6fe020cf7c0c20137434344ed7add6c4be51861e2d14cbda472a6ffb40221009be93722c1a3ad7d4cf91723700cb5486de5479d8c1b38ae4e8e5ba1638e9732";
      result = "valid";
      flags = [];
    },
    {
      tcId = 374;
      comment = "x-coordinate of the public key has many trailing 1's";
      key = "0425afd689acabaed67c1f296de59406f8c550f57146a0b4ec2c97876dfffffffffa46a76e520322dfbc491ec4f0cc197420fc4ea5883d8f6dd53c354bc4f67c35";
      msg = "4d657373616765";
      sig = "3045022100db09d8460f05eff23bc7e436b67da563fa4b4edb58ac24ce201fa8a358125057022046da116754602940c8999c8d665f786c50f5772c0a3cdbda075e77eabc64df16";
      result = "valid";
      flags = [];
    },
    {
      tcId = 375;
      comment = "y-coordinate of the public key has many trailing 1's";
      key = "04d12e6c66b67734c3c84d2601cf5d35dc097e27637f0aca4a4fdb74b6aadd3bb93f5bdff88bd5736df898e699006ed750f11cf07c5866cd7ad70c7121ffffffff";
      msg = "4d657373616765";
      sig = "30450220592c41e16517f12fcabd98267674f974b588e9f35d35406c1a7bb2ed1d19b7b8022100c19a5f942607c3551484ff0dc97281f0cdc82bc48e2205a0645c0cf3d7f59da0";
      result = "valid";
      flags = [];
    },
    {
      tcId = 376;
      comment = "y-coordinate of the public key has many trailing 1's";
      key = "04d12e6c66b67734c3c84d2601cf5d35dc097e27637f0aca4a4fdb74b6aadd3bb93f5bdff88bd5736df898e699006ed750f11cf07c5866cd7ad70c7121ffffffff";
      msg = "4d657373616765";
      sig = "3046022100be0d70887d5e40821a61b68047de4ea03debfdf51cdf4d4b195558b959a032b20221008266b4d270e24414ecacb14c091a233134b918d37320c6557d60ad0a63544ac4";
      result = "valid";
      flags = [];
    },
    {
      tcId = 377;
      comment = "y-coordinate of the public key has many trailing 1's";
      key = "04d12e6c66b67734c3c84d2601cf5d35dc097e27637f0aca4a4fdb74b6aadd3bb93f5bdff88bd5736df898e699006ed750f11cf07c5866cd7ad70c7121ffffffff";
      msg = "4d657373616765";
      sig = "3046022100fae92dfcb2ee392d270af3a5739faa26d4f97bfd39ed3cbee4d29e26af3b206a02210093645c80605595e02c09a0dc4b17ac2a51846a728b3e8d60442ed6449fd3342b";
      result = "valid";
      flags = [];
    },
    {
      tcId = 378;
      comment = "x-coordinate of the public key has many trailing 0's";
      key = "046d4a7f60d4774a4f0aa8bbdedb953c7eea7909407e3164755664bc2800000000e659d34e4df38d9e8c9eaadfba36612c769195be86c77aac3f36e78b538680fb";
      msg = "4d657373616765";
      sig = "30450220176a2557566ffa518b11226694eb9802ed2098bfe278e5570fe1d5d7af18a943022100ed6e2095f12a03f2eaf6718f430ec5fe2829fd1646ab648701656fd31221b97d";
      result = "valid";
      flags = [];
    },
    {
      tcId = 379;
      comment = "x-coordinate of the public key has many trailing 0's";
      key = "046d4a7f60d4774a4f0aa8bbdedb953c7eea7909407e3164755664bc2800000000e659d34e4df38d9e8c9eaadfba36612c769195be86c77aac3f36e78b538680fb";
      msg = "4d657373616765";
      sig = "3045022060be20c3dbc162dd34d26780621c104bbe5dace630171b2daef0d826409ee5c2022100bd8081b27762ab6e8f425956bf604e332fa066a99b59f87e27dc1198b26f5caa";
      result = "valid";
      flags = [];
    },
    {
      tcId = 380;
      comment = "x-coordinate of the public key has many trailing 0's";
      key = "046d4a7f60d4774a4f0aa8bbdedb953c7eea7909407e3164755664bc2800000000e659d34e4df38d9e8c9eaadfba36612c769195be86c77aac3f36e78b538680fb";
      msg = "4d657373616765";
      sig = "3046022100edf03cf63f658883289a1a593d1007895b9f236d27c9c1f1313089aaed6b16ae022100e5b22903f7eb23adc2e01057e39b0408d495f694c83f306f1216c9bf87506074";
      result = "valid";
      flags = [];
    },
  ];
};
