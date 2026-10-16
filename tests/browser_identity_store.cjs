const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("web/identity.js", "utf8");
let transaction;
let blockNextOpen = false;
let failNextOpen = false;
let closed = 0;
const db = {
  transaction() {
    transaction = {objectStore: () => ({get: () => ({})})};
    return transaction;
  },
  close() { closed += 1; },
};
const indexedDB = {
  open() {
    const request = {result: db};
    queueMicrotask(() => {
      if (blockNextOpen) {
        blockNextOpen = false;
        request.onblocked();
        queueMicrotask(() => request.onsuccess());
      } else if (failNextOpen) {
        failNextOpen = false;
        request.error = new Error("database opening failed");
        request.onerror();
        queueMicrotask(() => request.onsuccess());
      } else request.onsuccess();
    });
    return request;
  },
};
const context = vm.createContext({indexedDB, queueMicrotask, setTimeout, clearTimeout});
vm.runInContext(source, context);
const stalledRequest = {};
const stalled = vm.createContext({
  indexedDB: {open: () => stalledRequest},
  setTimeout: callback => { queueMicrotask(callback); return 1; },
  clearTimeout: () => {},
});
vm.runInContext(source, stalled);
let stalledAbort = 0;
const stalledTransaction = vm.createContext({
  indexedDB: {open: () => {
    const request = {result: {
      transaction: () => ({objectStore: () => ({get: () => ({})}), abort: () => { stalledAbort += 1; }}),
      close: () => { closed += 1; },
    }};
    queueMicrotask(() => request.onsuccess());
    return request;
  }},
  setTimeout: callback => { queueMicrotask(callback); return 1; },
  clearTimeout: () => {},
});
vm.runInContext(source, stalledTransaction);
const unsupported = vm.createContext({});
vm.runInContext(source, unsupported);

(async () => {
  await assert.rejects(unsupported.listBrowserIdentities(), /不支援本機密鑰儲存/);
  blockNextOpen = true;
  await assert.rejects(context.openIdentityStore(), /其他頁面阻擋/);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(closed, 1, "late blocked connection should be closed");
  await assert.rejects(stalled.openIdentityStore(), /開啟逾時/);
  stalledRequest.result = db;
  stalledRequest.onsuccess();
  assert.equal(closed, 2, "late timed-out connection should be closed");
  failNextOpen = true;
  await assert.rejects(context.openIdentityStore(), /database opening failed/);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(closed, 3, "late failed connection should be closed");
  await assert.rejects(stalledTransaction.identityOperation("readonly", store => store.get("missing")), /結果待確認/);
  assert.equal(stalledAbort, 1, "stalled transaction should be aborted when possible");
  assert.equal(closed, 4, "stalled transaction should close its connection");

  const pending = context.identityOperation("readonly", store => store.get("missing"));
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(transaction, "identity transaction should have started");
  transaction.onabort();
  await assert.rejects(pending, /本機密鑰操作已中止/);
  assert.equal(closed, 5, "aborted operation should close its connection");
})().catch(error => { process.stderr.write(String(error)); process.exitCode = 1; });
