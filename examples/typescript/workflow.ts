import { ClientIdentity, VectorNetworkClient } from "../../sdks/typescript/src/index.ts";

const endpoint = process.env.VNETWORK_ENDPOINT || "http://127.0.0.1:8080";
const networkId = process.env.VNETWORK_NETWORK_ID || "vector-devnet-1";
const vxFile = process.argv[2];

const identity = ClientIdentity.generate("ts-sdk-participant");
if (identity.participant_key.public_key_hex === identity.node_key.public_key_hex) {
  throw new Error("Participant and node keys must remain distinct");
}

const client = new VectorNetworkClient(endpoint, identity, networkId);
const info = await client.connect();
console.log(`Connected via TS SDK to ${info.network_id} (height=${info.height})`);

const joinRes = await client.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]);
console.log("Joined participant:", (joinRes.participant as { participant_id: string }).participant_id);

const submission = vxFile
  ? await client.submitVxFile(vxFile)
  : await client.submitProgram(
      "ts_workflow.vx",
      `
space create TsSdkSpace {
    name = "TypeScript SDK Space";
    visibility = "public";
}
region create TsSdkRegion in "TsSdkSpace" {
    prefix = "TSS";
    visibility = "public";
    section = 1;
}
wallet create TsWalletA in "TsSdkRegion" {
    name = "TS Wallet A";
}
wallet create TsWalletB in "TsSdkRegion" {
    name = "TS Wallet B";
}
token create TSTOK in "TsWalletA" {
    name = "TS Token";
    symbol = "TSTOK";
    dimensions = 3;
    vector = [12000, 1000, 0];
    max_supply = 12000;
    drain_bps = 100;
    purpose = "TS SDK integration";
    external_monetary_value = "None";
}
transfer "TSTOK" from "TsWalletA" to "TsWalletB" amount 200;
verify proof network;
`,
    );

if (submission.status !== "COMMITTED") {
  throw new Error(`Program failed: ${submission.status} ${submission.error_message}`);
}
console.log(`Committed TS program ${submission.program_id} root=${submission.final_state_root}`);

const tokenEntity = submission.created_entities.find((e) => e.kind === "token");
if (tokenEntity) {
  const rec = await client.verifyReconstruction("token", tokenEntity.id);
  if (!rec.verified) throw new Error("Token reconstruction failed");
  console.log(`Verified TS reconstruction for ${tokenEntity.id}: ${rec.reconstructed_hash}`);
}
