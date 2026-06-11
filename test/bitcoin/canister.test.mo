import Principal "mo:core/Principal";

import Canister "../../src/bitcoin/Canister";

// ─── Canister ID constants ─────────────────────────────────────────────────

assert Canister.MAINNET_CANISTER_ID == "ghsi2-tqaaa-aaaan-aaaca-cai";
assert Canister.TESTNET_CANISTER_ID == "g4xu7-jiaaa-aaaan-aaaaq-cai";
assert Canister.REGTEST_CANISTER_ID == "g4xu7-jiaaa-aaaan-aaaaq-cai";

// Testnet and regtest share the same canister (PocketIC local testing).
assert Canister.TESTNET_CANISTER_ID == Canister.REGTEST_CANISTER_ID;

// ─── createActor selects the correct canister principal per network ────────

let mainnetActor = Canister.createActor(#mainnet);
assert Principal.toText(Principal.fromActor(mainnetActor)) == Canister.MAINNET_CANISTER_ID;

let testnetActor = Canister.createActor(#testnet);
assert Principal.toText(Principal.fromActor(testnetActor)) == Canister.TESTNET_CANISTER_ID;

let regtestActor = Canister.createActor(#regtest);
assert Principal.toText(Principal.fromActor(regtestActor)) == Canister.REGTEST_CANISTER_ID;
