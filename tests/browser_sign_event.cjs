const fs = require("node:fs");
const vm = require("node:vm");
const {webcrypto} = require("node:crypto");
const source = fs.readFileSync("web/identity.js", "utf8");
const context = vm.createContext({crypto: webcrypto, TextEncoder, Uint8Array});
vm.runInContext(source, context);

(async () => {
  const pair = await webcrypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const author = Buffer.from(await webcrypto.subtle.exportKey("raw", pair.publicKey)).toString("hex");
  const domain = "a".repeat(64);
  const event = await context.DirectionIdentity.signBrowserEventWithKey(
    pair.privateKey, author, domain, null, "proposal", {id: "garden", title: "共同菜園"});
  const vote = await context.DirectionIdentity.signBrowserEventWithKey(
    pair.privateKey, author, domain, event, "vote", {proposal: "garden", approve: true});
  const eventId = await context.DirectionIdentity.eventId(event);
  const verified = await context.DirectionIdentity.verifyBrowserEvent(event, domain);
  const wrongDomainVerified = await context.DirectionIdentity.verifyBrowserEvent(event, "b".repeat(64));
  const changedEventVerified = await context.DirectionIdentity.verifyBrowserEvent(
    {...event, payload: {...event.payload, title: "另一個標題"}}, domain);
  if (!verified || wrongDomainVerified || changedEventVerified) throw new Error("Browser signature verification mismatch");
  const headVote = await context.DirectionIdentity.signBrowserEventWithKey(
    pair.privateKey, author, domain, {author, next_sequence: 2, previous: eventId},
    "vote", {proposal: "garden", approve: true});
  const other = "b".repeat(64);
  try {
    await context.DirectionIdentity.signBrowserEventWithKey(
      pair.privateKey, other, domain, null, "proposal", {id: "wrong-key", title: "錯誤身分"});
    throw new Error("Mismatched browser private key was accepted");
  } catch (error) {
    if (error.message === "Mismatched browser private key was accepted") throw error;
  }
  const genesis = context.DirectionIdentity.browserGenesis([author], "test-net", 100, `\n${other}\n`);
  const genesisDomain = await context.DirectionIdentity.genesisDomain(genesis.network_id, genesis.balances);
  try {
    await context.DirectionIdentity.genesisDomain("test-net", {
      [author]: Number.MAX_SAFE_INTEGER, [other]: 1});
    throw new Error("Unsafe total genesis supply was accepted");
  } catch (error) {
    if (error.message === "Unsafe total genesis supply was accepted") throw error;
  }
  if (Object.keys(genesis.balances).length !== 2 || genesis.balances[other] !== 100) {
    throw new Error("Another port's public identity was not included");
  }
  for (const [local, external] of [[[author], author], [[], other]]) {
    try {
      context.DirectionIdentity.browserGenesis(local, "test-net", 100, external);
      throw new Error("Invalid public identity collection was accepted");
    } catch (error) {
      if (error.message === "Invalid public identity collection was accepted") throw error;
    }
  }
  process.stdout.write(JSON.stringify({domain, event, eventId, vote, headVote, genesis, genesisDomain}));
})().catch(error => { process.stderr.write(String(error)); process.exitCode = 1; });
