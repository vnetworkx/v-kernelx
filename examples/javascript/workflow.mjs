import { ClientIdentity, VectorNetworkClient } from "../../sdks/javascript/index.js";

const endpoint = process.env.VNETWORK_ENDPOINT || "http://127.0.0.1:8080";
const networkId = process.env.VNETWORK_NETWORK_ID || "vnetwork-devnet-1";
const vxFile = process.argv[2];

const identity = ClientIdentity.generate("js-sdk-participant");
if (identity.participant_key.public_key_hex === identity.node_key.public_key_hex) {
  throw new Error("Participant and node keys must remain distinct");
}

const client = new VectorNetworkClient(endpoint, identity, networkId);
const info = await client.connect();
console.log(`Connected via JS SDK to ${info.network_id} (height=${info.height})`);

const wsEvents = [];
const ws = client.subscribeEvents((evt) => wsEvents.push(evt));

const joinRes = await client.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]);
console.log("Joined participant:", joinRes.participant.participant_id);

const submission = vxFile
  ? await client.submitVxFile(vxFile)
  : await client.submitProgram(
      "js_workflow.vx",
      `
space create JsSdkSpace {
    name = "JavaScript SDK Space";
    visibility = "public";
}
region create JsSdkRegion in "JsSdkSpace" {
    prefix = "JSS";
    visibility = "public";
    section = 1;
}
wallet create JsWalletA in "JsSdkRegion" {
    name = "JS Wallet A";
}
wallet create JsWalletB in "JsSdkRegion" {
    name = "JS Wallet B";
}
token create JSTOK in "JsWalletA" {
    name = "JS Token";
    symbol = "JSTOK";
    dimensions = 3;
    vector = [18000, 1000, 0];
    max_supply = 18000;
    drain_bps = 100;
    purpose = "JS SDK integration";
    external_monetary_value = "None";
}
contract create JsContract {
    region = "JsSdkRegion";
    action approve(tier="js", limit=500);
}
contract execute "JsContract".approve(tier="js", limit=500);
transfer "JSTOK" from "JsWalletA" to "JsWalletB" amount 300;
verify proof network;
`,
    );

if (submission.status !== "COMMITTED") {
  throw new Error(`Program failed: ${submission.status} ${submission.error_message}`);
}
console.log(`Committed JS program ${submission.program_id} root=${submission.final_state_root}`);

const tokenEntity = submission.created_entities.find((e) => e.kind === "token");
if (tokenEntity) {
  const rec = await client.verifyReconstruction("token", tokenEntity.id);
  if (!rec.verified) throw new Error("Token reconstruction failed");
  console.log(`Verified reconstruction for ${tokenEntity.id}: ${rec.reconstructed_hash}`);
}

const proofs = await client.getLedgerProofs();
if (!proofs.chain_valid) throw new Error("Ledger proof check failed");
ws.close();
console.log(`JS SDK workflow succeeded (proofs=${proofs.event_count} events, ws=${wsEvents.length})`);
