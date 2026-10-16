/* Experimental browser-local test identity. Private keys are nonextractable. */
const DB_NAME = "direction-lab-local-test-keys";
const STORE_NAME = "identities";

function openIdentityStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    let blocked = false;
    const timer = setTimeout(() => {
      blocked = true;
      reject(new Error("本機密鑰資料庫開啟逾時；請重新載入頁面後重試。"));
    }, 10000);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME, {keyPath: "id"});
    request.onsuccess = () => {
      clearTimeout(timer);
      if (blocked) request.result.close();
      else resolve(request.result);
    };
    request.onblocked = () => {
      clearTimeout(timer);
      blocked = true;
      reject(new Error("本機密鑰資料庫被其他頁面阻擋；請關閉舊頁面後重試。"));
    };
    request.onerror = () => {
      clearTimeout(timer);
      blocked = true;
      reject(request.error);
    };
  });
}

async function identityOperation(mode, callback) {
  const db = await openIdentityStore();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, mode);
      const request = callback(transaction.objectStore(STORE_NAME));
      let settled = false;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        callback(value);
      };
      const timer = setTimeout(() => {
        finish(reject, new Error("本機密鑰操作逾時，結果待確認；請重新讀取身分清單。"));
        try { transaction.abort(); } catch { /* Transaction may already be inactive. */ }
      }, 10000);
      transaction.oncomplete = () => finish(resolve, request.result);
      request.onerror = () => finish(reject, request.error);
      transaction.onerror = () => finish(reject, transaction.error);
      transaction.onabort = () => finish(reject, transaction.error || new Error("本機密鑰操作已中止。"));
    });
  } finally { db.close(); }
}

async function createBrowserIdentity() {
  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) {
    throw new Error("此瀏覽器不支援安全的本機密鑰儲存。");
  }
  const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const id = Array.from(raw, byte => byte.toString(16).padStart(2, "0")).join("");
  await identityOperation("readwrite", store => store.add({id, privateKey: pair.privateKey}));
  return id;
}

async function listBrowserIdentities() {
  if (!globalThis.indexedDB) throw new Error("此瀏覽器不支援本機密鑰儲存。");
  return identityOperation("readonly", store => store.getAllKeys());
}

function browserGenesis(ids, networkId, credits, additionalIds = "") {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(networkId) || networkId === "demo") {
    throw new Error("網路 ID 須為 1–64 個英數字、點、底線或連字號，且不能是 demo。");
  }
  if (!Number.isSafeInteger(credits) || credits < 0 || credits > 1000000) {
    throw new Error("每人測試點數須為 0–1000000 的整數。");
  }
  if (!Array.isArray(ids) || !ids.length || typeof additionalIds !== "string") {
    throw new Error("請先在此瀏覽器建立至少一個公鑰身分。");
  }
  const combined = [...ids, ...additionalIds.trim().split(/[\s,;]+/).filter(Boolean)];
  if (combined.length < 2 || new Set(combined).size !== combined.length
      || combined.some(id => !/^[a-f0-9]{64}$/.test(id))) {
    throw new Error("至少需要兩個不同的有效公鑰 ID；請檢查其他節點貼上的 ID。");
  }
  const balances = Object.fromEntries(combined.map(id => [id, credits]));
  return {network_id: networkId, balances};
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function eventId(signedEvent) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(signedEvent))));
}

async function genesisDomain(networkId, balances) {
  if (typeof networkId !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(networkId) || networkId === "demo" ||
      !balances || typeof balances !== "object" || Array.isArray(balances) ||
      !Object.keys(balances).length || Object.entries(balances).some(([id, amount]) =>
        !/^[a-f0-9]{64}$/.test(id) || !Number.isSafeInteger(amount) || amount < 0)) {
    throw new Error("公鑰測試網路初始配置無效。");
  }
  const total = Object.values(balances).reduce((sum, amount) => sum + amount, 0);
  if (!Number.isSafeInteger(total)) throw new Error("初始測試點數總量超出瀏覽器安全整數範圍。");
  return eventId({network_id: networkId, balances});
}

async function verifyBrowserEvent(event, signatureDomain) {
  if (!event || typeof event !== "object" || Array.isArray(event) ||
      Object.keys(event).sort().join(",") !== "author,kind,payload,previous,sequence,signature" ||
      !/^[a-f0-9]{64}$/.test(signatureDomain) || !/^[a-f0-9]{64}$/.test(event.author) ||
      !/^[a-f0-9]{128}$/.test(event.signature)) return false;
  try {
    const {signature, ...unsigned} = event;
    const publicKey = await crypto.subtle.importKey("raw", Uint8Array.from(event.author.match(/../g), byte => parseInt(byte, 16)),
      "Ed25519", false, ["verify"]);
    const domain = new TextEncoder().encode(`direction-lab:event:v1\0${signatureDomain}\0`);
    const message = new TextEncoder().encode(canonical(unsigned));
    const bytes = new Uint8Array(domain.length + message.length);
    bytes.set(domain);
    bytes.set(message, domain.length);
    return await crypto.subtle.verify("Ed25519", publicKey,
      Uint8Array.from(signature.match(/../g), byte => parseInt(byte, 16)), bytes);
  } catch { return false; }
}

async function signBrowserEvent(author, signatureDomain, head, kind, payload) {
  const record = await identityOperation("readonly", store => store.get(author));
  if (!record?.privateKey) throw new Error("此瀏覽器沒有該身分的私鑰。");
  return signBrowserEventWithKey(record.privateKey, author, signatureDomain, head, kind, payload);
}

async function signBrowserEventWithKey(privateKey, author, signatureDomain, head, kind, payload) {
  if (!/^[a-f0-9]{64}$/.test(signatureDomain)) throw new Error("網路簽章域無效。");
  const currentHead = head && Object.hasOwn(head, "next_sequence");
  const previous = currentHead ? head.previous
    : head ? hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(head)))) : "GENESIS";
  const sequence = currentHead ? head.next_sequence : head ? head.sequence + 1 : 1;
  if ((currentHead && head.author !== author) || !Number.isSafeInteger(sequence) || sequence < 1 ||
      (sequence === 1) !== (previous === "GENESIS") ||
      (previous !== "GENESIS" && !/^[a-f0-9]{64}$/.test(previous))) throw new Error("作者事件序號無效。");
  const unsigned = {author, sequence, previous, kind, payload};
  const domain = new TextEncoder().encode(`direction-lab:event:v1\0${signatureDomain}\0`);
  const message = new TextEncoder().encode(canonical(unsigned));
  const bytes = new Uint8Array(domain.length + message.length);
  bytes.set(domain);
  bytes.set(message, domain.length);
  const signature = hex(await crypto.subtle.sign("Ed25519", privateKey, bytes));
  const signed = {...unsigned, signature};
  if (!await verifyBrowserEvent(signed, signatureDomain))
    throw new Error("本機私鑰與作者公鑰不符，未送出事件。");
  return signed;
}

globalThis.DirectionIdentity = {createBrowserIdentity, listBrowserIdentities, browserGenesis, signBrowserEvent, eventId,
                                verifyBrowserEvent, genesisDomain,
                                signBrowserEventWithKey};
