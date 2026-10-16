const $ = id => document.getElementById(id);
const people = ["alice", "bob", "chen"];
const notice = message => { $("notice").textContent = message; };
const identityLabel = id => /^[0-9a-f]{64}$/.test(id) ? `${id.slice(0, 12)}…${id.slice(-8)}` : id;
let nodeOnline = false;
let syncPending = false;
let comparePending = false;
let exportPending = false;
let renderedConflictsKey = null;
let lookupSequence = 0;
let syncRunning = false;
let lastRefreshAt = null;
let lastSuccessfulRefreshMs = null;
const pendingKey = "direction-lab:pending-test-event";
let pendingAttempt = null;
let pendingStorageAvailable = true;
try { pendingAttempt = sessionStorage.getItem(pendingKey); }
catch { pendingStorageAvailable = false; }
let submissionUncertain = Boolean(pendingAttempt);

function rememberPendingAttempt(id) {
  pendingAttempt = id || "unknown";
  try { sessionStorage.setItem(pendingKey, pendingAttempt); }
  catch { pendingStorageAvailable = false; }
}

function forgetPendingAttempt() {
  pendingAttempt = null;
  try { sessionStorage.removeItem(pendingKey); } catch { /* Storage may be unavailable. */ }
}

function pauseNodeActions(reason = "節點無法連線") {
  nodeOnline = false;
  lookupSequence++;
  $("lookup-result").textContent = "節點狀態已失效；先前的單筆事件核對不可沿用，請重新連線後查詢。";
  renderedProposalsKey = null;
  const lastRead = lastRefreshAt ? `上次成功讀取：${lastRefreshAt}。` : "尚未成功讀取節點。";
  $("connection-state").textContent = `${reason}；${lastRead}畫面資料可能過期，交易與投票已暫停。`;
  $("connection-state").className = "danger";
  $("state-warning").textContent = `${reason}，無法確認本機事件檔完整性。`;
  $("state-warning").className = "danger";
  $("balance-warning").textContent = `${reason}；以下數字可能過期，不可視為可用點數。`;
  $("balance-warning").className = "danger";
  $("sync").disabled = true;
  $("compare-peers").disabled = true;
  $("export-events").disabled = true;
  for (const form of [$("transfer-form"), $("proposal-form")]) {
    for (const control of form.elements) control.disabled = true;
  }
  for (const control of $("lookup-form").elements) control.disabled = true;
  for (const control of $("proposals").querySelectorAll("button, select")) control.disabled = true;
}

function identityOption(id) {
  const option = element("option", identityLabel(id));
  option.value = id;
  option.title = id;
  return option;
}

async function refreshBrowserIdentities() {
  const list = await DirectionIdentity.listBrowserIdentities();
  renderBrowserIdentities(list);
}

let renderedIdentityKey = null;
let renderedProposalsKey = null;
function renderBrowserIdentities(list) {
  const identityKey = JSON.stringify(list);
  if (identityKey === renderedIdentityKey) return;
  renderedIdentityKey = identityKey;
  const target = $("browser-identities");
  target.replaceChildren();
  for (const id of list) {
    const row = element("div", "", "row public-id");
    const label = element("span", id);
    const copy = element("button", "複製公鑰 ID", "secondary");
    copy.type = "button";
    copy.addEventListener("click", () => {
      if (!navigator.clipboard?.writeText) {
        notice("此瀏覽器無法自動複製；請手動選取公鑰 ID。");
        return;
      }
      navigator.clipboard.writeText(id)
        .then(() => notice("已複製公鑰 ID；可貼到另一節點的測試網路設定。"))
        .catch(() => notice("複製失敗；請手動選取公鑰 ID。"));
    });
    row.append(label, copy);
    target.append(row);
  }
  if (!list.length) target.textContent = "此瀏覽器尚無本機測試身分。";
}

async function request(path, body, timeoutMs = body === undefined ? 10000 : 0) {
  const controller = timeoutMs ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    const options = body === undefined ? {} : {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
    };
    if (controller) options.signal = controller.signal;
    const response = await fetch(path, options);
    const data = await response.json();
    if (!response.ok) {
      const problem = data.reason || data.error || `HTTP ${response.status}`;
      const error = new Error(problem === "state_unavailable"
        ? "節點無法保存狀態，事件未被接受；請檢查本機儲存後再試。" : problem);
      error.definitiveRejection = response.status < 500 || problem === "state_unavailable";
      throw error;
    }
    return data;
  } catch (error) {
    if (error?.name === "AbortError")
      throw new Error("節點請求逾時；若剛送出事件，結果可能已寫入，請先核對。");
    throw error;
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

function element(tag, text, className) {
  const item = document.createElement(tag);
  item.textContent = text;
  if (className) item.className = className;
  return item;
}

function options(select, values) {
  if (select.options.length === values.length &&
      values.every((value, index) => select.options[index].value === value)) return;
  const selected = select.value;
  select.replaceChildren(...values.map(identityOption));
  if (values.includes(selected)) select.value = selected;
}

function chooseDistinctRecipient() {
  const author = $("transfer-form").elements.author.value;
  const recipient = $("transfer-form").elements.recipient;
  if (recipient.value === author) {
    const other = [...recipient.options].find(option => option.value !== author);
    recipient.value = other ? other.value : "";
  }
  return Boolean(recipient.value && recipient.value !== author);
}

let refreshSequence = 0;
let observedNetwork = null;
async function refresh() {
  if (lastSuccessfulRefreshMs !== null && Date.now() - lastSuccessfulRefreshMs > 10000)
    pauseNodeActions("節點超過十秒沒有成功更新");
  const sequence = ++refreshSequence;
  let state, eventData, localKeys, identityError = null;
  try {
    [state, eventData] = await Promise.all([request("/status"), request("/events/recent")]);
    localKeys = state.identity_mode === "public-key"
      ? await DirectionIdentity.listBrowserIdentities().catch(error => {
        identityError = error;
        return [];
      }) : [];
  } catch (error) {
    if (sequence === refreshSequence) pauseNodeActions();
    throw error;
  }
  if (sequence !== refreshSequence) return;
  let configError = null;
  if (state.identity_mode === "public-key") {
    try {
      if (await DirectionIdentity.genesisDomain(state.network_id, state.genesis) !== state.signature_domain)
        throw new Error("節點宣稱的網路簽章域與初始配置不符");
    } catch (error) { configError = error; }
  }
  const network = `${state.identity_mode}:${state.signature_domain}`;
  if (observedNetwork === null && !configError) observedNetwork = network;
  else if (observedNetwork !== null && observedNetwork !== network)
    configError = new Error("此頁開啟期間節點測試網路已變更；請重新載入並核對配置");
  if (sequence !== refreshSequence) return;
  if (state.identity_mode === "public-key") {
    if (identityError) {
      renderedIdentityKey = null;
      $("browser-identities").textContent = "無法讀取本機身分；請檢查瀏覽器儲存。";
    }
    else renderBrowserIdentities(localKeys);
  }
  if (state.events !== eventData.event_count || state.process_epoch !== eventData.process_epoch) {
    pauseNodeActions("節點在讀取期間重啟或事件變動，等待重新整理");
    return;
  }
  $("peer-name").textContent = state.peer;
  if (state.peer === "left" || state.peer === "right") {
    const port = Number(location.port);
    const otherPort = state.peer === "right" ? port - 1 : port + 1;
    $("genesis-command").textContent = `python node_server.py --name ${state.peer} --port ${port} --public-genesis data/peers/direction-lab-genesis.json --state data/peers/public-${state.peer}.json`;
    if (otherPort > 0 && otherPort <= 65535) {
      const leftPort = state.peer === "right" ? otherPort : port;
      const rightPort = state.peer === "right" ? port : otherPort;
      $("pair-command").textContent = `python run_local_pair.py --left-port ${leftPort} --right-port ${rightPort} --public-genesis data/peers/direction-lab-genesis.json`;
      $("copy-pair-command").disabled = false;
    } else {
      $("pair-command").textContent = "相鄰連接埠超出範圍；請自行指定兩個有效連接埠。";
      $("copy-pair-command").disabled = true;
    }
    $("copy-genesis-command").disabled = false;
  } else {
    $("genesis-command").textContent = "請依此節點實際名稱與連接埠指定公鑰設定及獨立狀態檔。";
    $("pair-command").textContent = "此節點不是預設 left/right；請依實際配置啟動雙節點。";
    $("copy-genesis-command").disabled = true;
    $("copy-pair-command").disabled = true;
  }
  $("event-count").textContent = state.events;
  $("state-warning").textContent = state.state_integrity === "legacy_unchecked"
    ? "此節點載入舊版事件檔，沒有摘要可排除完整但遭截斷的紀錄；請先核對其他節點及原始紀錄。"
    : state.state_integrity === "verified" ? "本機事件檔摘要已核對；這不代表防竄改或交易最終性。"
      : state.state_persistence_enabled
        ? "已設定本機狀態檔；目前尚無事件檔，第一筆接受的事件寫入後才可測試重啟恢復。"
        : "未設定本機狀態檔；重啟此節點將遺失本機事件。";
  $("state-warning").className = state.state_integrity === "legacy_unchecked"
    || !state.state_persistence_enabled ? "danger" : "";
  const peerCount = Array.isArray(state.peers) ? state.peers.length : 0;
  syncRunning = Boolean(state.sync_running);
  $("peer-count").textContent = String(peerCount);
  const autoSync = state.auto_sync;
  const autoResult = autoSync?.last_result;
  const checkedAt = autoResult?.checked_at ? new Date(autoResult.checked_at) : null;
  const checkedLabel = checkedAt && !Number.isNaN(checkedAt.getTime())
    ? `（${checkedAt.toLocaleTimeString()}）` : "";
  $("auto-sync").textContent = state.sync_running ? "正在同步；請等待本輪結果"
    : !autoSync?.enabled ? "未啟用，需手動同步"
    : !autoResult ? "等待首次檢查"
      : autoResult.state === "no_peers" ? `尚無相鄰節點${checkedLabel}`
        : autoResult.state === "ok" ? `上次檢查無未解決項${checkedLabel}`
          : `上次檢查有問題${checkedLabel}，請手動同步查看`;
  $("auto-sync").className = autoResult && !["ok", "no_peers"].includes(autoResult.state) ? "danger" : "";
  $("sync").disabled = syncPending || syncRunning || peerCount === 0;
  $("compare-peers").disabled = comparePending || peerCount === 0;
  $("export-events").disabled = exportPending;
  for (const control of $("lookup-form").elements) control.disabled = false;
  $("peer-warning").textContent = peerCount === 0
    ? "尚未設定相鄰節點：此節點不會主動轉送事件；請以 --peer 連接另一節點。"
    : `已設定 ${peerCount} 個本機相鄰節點；是否已收到事件，仍須檢查同步結果。`;
  const peerLinks = $("peer-links");
  peerLinks.replaceChildren();
  for (const peer of state.peers || []) {
    try {
      const url = new URL(peer);
      if (url.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(url.hostname)
          || url.username || url.password || url.pathname !== "/") continue;
      const link = element("a", `開啟相鄰節點 ${url.host}`);
      link.href = url.href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      peerLinks.append(link);
    } catch { /* Invalid peer URLs are never rendered as links. */ }
  }
  $("finality").textContent = state.finality === "insufficient" ? "有衝突，未能確認" : "暫定，尚無最終性";
  $("finality").className = state.finality === "insufficient" ? "danger" : "";
  const signedMode = state.identity_mode === "public-key";
  $("intro").textContent = signedMode
    ? "這是僅限本機的無價值公鑰測試網路。節點不保存私鑰；此瀏覽器只會使用自己儲存的不可匯出私鑰簽署事件。"
    : "在這個節點建立交易或提案，其他連線節點會收到同一事件。這是本機實驗介面；Alice、Bob、Chen 是公開的測試身分。";
  $("identity-mode").textContent = configError
    ? `測試網路配置無法核對：${configError.message}；交易與投票已停用。`
    : signedMode
      ? identityError
        ? `無法讀取此瀏覽器的測試身分：${identityError.message}；簽署操作已停用。`
        : "公鑰驗證模式：只可使用此瀏覽器持有、且已列入初始配置的身分簽署測試事件。"
      : "公開測試身分模式：任何人都能操作，僅限無價值示範。";
  $("identity-mode").className = identityError || configError ? "danger" : "";
  $("disclaimer").textContent = signedMode
    ? "公鑰模式仍僅限本機測試；瀏覽器私鑰無備份與審計，沒有真實資產、權利裁決或正式交易最終性。"
    : "測試身分使用公開示範密鑰，沒有真實資產、權利裁決或正式交易最終性。";
  const owned = localKeys.filter(id => Object.hasOwn(state.balances, id));
  if (signedMode) {
    options($("transfer-form").elements.author, owned);
    options($("transfer-form").elements.recipient, Object.keys(state.balances));
    options($("proposal-form").elements.author, owned);
  }
  const distinctRecipient = chooseDistinctRecipient();
  const actionsBlocked = state.finality === "insufficient" || submissionUncertain || submissionPending || Boolean(configError);
  for (const form of [$("transfer-form"), $("proposal-form")]) {
    for (const control of form.elements) control.disabled = actionsBlocked || (signedMode && !owned.length);
  }
  $("transfer-form").querySelector("button[type=submit]").disabled = actionsBlocked || !distinctRecipient || (signedMode && !owned.length);
  $("balance-warning").textContent = state.balances_disputed
    ? "偵測到互相衝突的事件；以下只是本節點依先到事件計算的數字，其他節點可能不同。本節點已暫停建立新交易與投票。"
    : "僅為本節點暫定測試點數；尚無跨網共識或最終結算。";
  $("balance-warning").className = state.balances_disputed ? "danger" : "";
  const balances = $("balances");
  balances.replaceChildren();
  for (const [name, amount] of Object.entries(state.balances)) {
    const row = element("div", "", "row");
    const label = element("span", identityLabel(name));
    label.title = name;
    row.append(label, element("strong", String(amount)));
    balances.append(row);
  }
  const proposals = $("proposals");
  const proposalsKey = JSON.stringify([state.proposals, signedMode, owned, actionsBlocked]);
  if (proposalsKey !== renderedProposalsKey) {
    const priorVoters = new Map([...proposals.querySelectorAll("article[data-proposal-id]")]
      .map(card => [card.dataset.proposalId, card.querySelector("select")?.value]));
    proposals.replaceChildren();
    for (const [id, item] of Object.entries(state.proposals)) {
      const card = element("article", "", "proposal");
      card.dataset.proposalId = id;
      card.append(element("h3", item.title), element("p", `提案人 ${identityLabel(item.author)} · 同意 ${item.yes} · 反對 ${item.no}`));
      const controls = element("div", "", "vote-controls");
      const voter = document.createElement("select");
      voter.setAttribute("aria-label", `${item.title} 的投票人`);
      for (const person of signedMode ? owned : people) voter.append(identityOption(person));
      if ([...voter.options].some(option => option.value === priorVoters.get(id))) voter.value = priorVoters.get(id);
      controls.append(voter);
      const voteButtons = [];
      for (const [label, approve] of [["同意", true], ["反對", false]]) {
        const button = element("button", label);
        button.type = "button";
        button.addEventListener("click", () => submit({author: voter.value, kind: "vote", payload: {proposal: id, approve}}));
        controls.append(button);
        voteButtons.push(button);
      }
      const updateVoteButtons = () => {
        for (const button of voteButtons) button.disabled = actionsBlocked || !voter.value || Object.hasOwn(item.votes, voter.value);
      };
      voter.addEventListener("change", updateVoteButtons);
      updateVoteButtons();
      voter.disabled = actionsBlocked;
      if (!signedMode || owned.length) card.append(controls);
      proposals.append(card);
    }
    if (!proposals.childElementCount) proposals.append(element("p", "目前沒有提案。"));
    renderedProposalsKey = proposalsKey;
  }
  const history = $("history");
  history.replaceChildren();
  const recent = eventData.events.reverse();
  for (const event of recent) {
    const description = event.kind === "transfer"
      ? `${identityLabel(event.author)} → ${identityLabel(event.payload.recipient)} · ${event.payload.amount} 點`
      : event.kind === "proposal"
        ? `${identityLabel(event.author)} 建立提案：${event.payload.title}`
        : `${identityLabel(event.author)} 對提案投了${event.payload.approve ? "同意" : "反對"}票`;
    const row = element("div", "", "row");
    const details = element("div", description);
    const id = element("code", `ID ${event.id.slice(0, 16)}…`);
    id.title = event.id;
    details.append(document.createElement("br"), id);
    const copy = element("button", "複製完整 ID", "secondary");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(event.id);
        notice("已複製事件 ID；請到相鄰節點核對同一筆暫定事件。");
      } catch { notice(`無法自動複製；完整 ID：${event.id}`); }
    });
    const lookup = element("button", "查詢", "secondary");
    lookup.type = "button";
    lookup.addEventListener("click", () => {
      $("lookup-form").elements.event_id.value = event.id;
      lookupById(event.id);
    });
    const controls = element("div", "", "vote-controls");
    controls.append(copy, lookup);
    row.append(details, controls);
    history.append(row);
  }
  if (!recent.length) history.textContent = "目前沒有事件。";
  const conflicts = Object.entries(state.conflicts).sort(([left], [right]) => left.localeCompare(right));
  const conflictsKey = JSON.stringify(conflicts);
  if (conflictsKey !== renderedConflictsKey) {
    const target = $("conflicts");
    target.replaceChildren();
    if (!conflicts.length) target.textContent = "目前沒有已知衝突。";
    else {
      target.append(element("p", "本節點已暫停建立新交易、提案與投票；同步仍可能補入有效簽章的事件。"));
      for (const [slot, ids] of conflicts) {
        const row = element("div", "", "row");
        row.append(element("span", `${slot}：${ids.length} 個互相衝突的事件`));
        const controls = element("div", "", "vote-controls");
        for (const id of ids) {
          if (typeof id !== "string" || !/^[0-9a-f]{64}$/.test(id)) continue;
          const button = element("button", `查詢 ${id.slice(0, 12)}…`, "secondary");
          button.type = "button";
          button.title = id;
          button.addEventListener("click", () => {
            $("lookup-form").elements.event_id.value = id;
            lookupById(id);
          });
          const copy = element("button", "複製完整 ID", "secondary");
          copy.type = "button";
          copy.title = id;
          copy.addEventListener("click", async () => {
            try {
              await navigator.clipboard.writeText(id);
              notice("已複製衝突事件的完整 ID；請在另一節點獨立核對。");
            } catch {
              notice("無法複製；請用查詢欄中的完整 ID 手動選取。");
              $("lookup-form").elements.event_id.value = id;
            }
          });
          controls.append(button, copy);
        }
        row.append(controls);
        target.append(row);
      }
    }
    renderedConflictsKey = conflictsKey;
  }
  nodeOnline = true;
  lastSuccessfulRefreshMs = Date.now();
  lastRefreshAt = new Date().toLocaleTimeString("zh-TW", {hour12: false});
  $("connection-state").textContent = `節點已連線；上次讀取：${lastRefreshAt}。畫面仍為暫定狀態。`;
  $("connection-state").className = "";
  return !configError;
}

let submissionPending = false;
function disableSubmissionControls() {
  renderedProposalsKey = null;
  for (const form of [$("transfer-form"), $("proposal-form")]) {
    for (const control of form.elements) control.disabled = true;
  }
  for (const control of $("proposals").querySelectorAll("button, select")) control.disabled = true;
}

async function lookupById(eventId) {
  const sequence = ++lookupSequence;
  const result = $("lookup-result");
  if (!nodeOnline) {
    result.textContent = "節點未連線，無法查詢。";
    return;
  }
  result.textContent = "正在查詢此節點保存的暫定事件…";
  try {
    const [record, state] = await Promise.all([
      request(`/events/id/${encodeURIComponent(eventId)}`), request("/status")]);
    if (sequence !== lookupSequence) return;
    const calculatedId = record.event ? await DirectionIdentity.eventId(record.event) : null;
    const genesisMatches = state.identity_mode !== "public-key" ||
      await DirectionIdentity.genesisDomain(state.network_id, state.genesis) === state.signature_domain;
    const browserValid = state.identity_mode === "public-key"
      ? Object.hasOwn(state.genesis, record.event?.author) &&
        await DirectionIdentity.verifyBrowserEvent(record.event, state.signature_domain)
      : state.identity_mode === "demo";
    if (sequence !== lookupSequence) return;
    if (record.id !== eventId || calculatedId !== eventId || record.signature_valid !== true ||
        !genesisMatches || !browserValid) {
      result.textContent = "節點回覆與查詢 ID 或簽章驗證不符；請勿視為已核對。";
      return;
    }
    const event = record.event;
    const detail = event.kind === "transfer"
      ? `交易：${identityLabel(event.author)} → ${identityLabel(event.payload.recipient)}，${event.payload.amount} 測試點數`
      : event.kind === "proposal"
        ? `提案：${event.payload.title}；發起人 ${identityLabel(event.author)}`
        : event.kind === "vote"
          ? `投票：${identityLabel(event.author)} 對提案 ${event.payload.proposal} 投了${event.payload.approve ? "同意" : "反對"}票`
          : `事件種類：${event.kind}`;
    let peerNote = "尚未核對相鄰節點。";
    try {
      const comparison = await request(`/events/id/${encodeURIComponent(eventId)}/peers`);
      if (sequence !== lookupSequence) return;
      if (comparison.event !== eventId || typeof comparison.peers !== "object"
          || comparison.peers === null || Array.isArray(comparison.peers)) {
        throw new Error("相鄰節點核對回覆與事件 ID 不符");
      }
      const entries = Object.entries(comparison.peers || {});
      const states = entries.map(([, state]) => state);
      const observed = states.filter(state => state === "observed").length;
      const missing = states.filter(state => state === "not_visible").length;
      const uncertain = states.length - observed - missing;
      const labels = {
        observed: "同一簽章事件可見", not_visible: "目前不可見",
        incomplete: "查詢期間狀態改變，請重查", incompatible: "網路設定不相容",
        invalid: "回覆無法驗證", unreachable: "無法連線"
      };
      const details = entries.map(([peer, state], index) => {
        let name = `節點 ${index + 1}`;
        try { name = new URL(peer).host; } catch { /* Keep a safe generic label. */ }
        return `${name}：${labels[state] || "狀態不明"}`;
      }).join("；");
      peerNote = states.length
        ? `相鄰節點：${observed} 個回報同一簽章事件、${missing} 個目前不可見、${uncertain} 個無法核對。${details}。不可見不等於事件不存在。`
        : "尚未設定相鄰節點，無法交叉核對。";
      if (comparison.local_changed) peerNote += "本節點在查詢期間新增事件，請重新核對。";
    } catch (error) {
      if (sequence !== lookupSequence) return;
      peerNote = `相鄰節點核對失敗：${error.message}。`;
    }
    const verificationNote = state.identity_mode === "public-key"
      ? "此瀏覽器也以公鑰重新驗證簽章。" : "示範模式由本機節點回報簽章有效。";
    const conflictSlots = Object.entries(state.conflicts || {})
      .filter(([, ids]) => Array.isArray(ids) && ids.includes(eventId))
      .map(([slot]) => slot);
    const conflictNote = conflictSlots.length
      ? `警告：此事件屬於本節點已知衝突（${conflictSlots.join("、")}）；有效簽章與相鄰節點可見都不能裁決哪筆應生效。`
      : "";
    result.textContent = `本節點保存的暫定事件。${verificationNote}${detail}。${conflictNote}${peerNote}不代表最終結算。`;
  } catch (error) {
    if (sequence !== lookupSequence) return;
    result.textContent = error.message === "event_not_found"
      ? "本節點沒有這筆可公開查詢的事件；可先同步，再重新核對。"
      : `查詢失敗：${error.message}`;
  }
}

$("lookup-form").addEventListener("submit", event => {
  event.preventDefault();
  lookupById(String(new FormData(event.currentTarget).get("event_id")).trim());
});
async function submit(action) {
  if (submissionUncertain) {
    notice(`上一筆事件送出結果待確認；請先核對事件清單。${pendingStorageAvailable ? "核對後可重新載入頁面。" : "瀏覽器無法保存待確認標記，請勿重新載入本頁。"}不要直接重送。`);
    return false;
  }
  if (!nodeOnline) {
    notice("節點未連線，請等待狀態恢復後再操作。");
    return false;
  }
  if (submissionPending) {
    notice("上一筆事件尚在處理，請稍候。");
    return false;
  }
  submissionPending = true;
  disableSubmissionControls();
  let sendStarted = false;
  let attemptedId = null;
  let responseAccepted = false;
  try {
    notice("正在簽署並送出事件…");
    const state = await request("/status");
    if (observedNetwork !== null && observedNetwork !== `${state.identity_mode}:${state.signature_domain}`)
      throw new Error("此頁開啟期間節點測試網路已變更；請重新載入並核對配置。");
    let result;
    if (state.identity_mode === "public-key") {
      if (await DirectionIdentity.genesisDomain(state.network_id, state.genesis) !== state.signature_domain)
        throw new Error("節點宣稱的網路簽章域與初始配置不符，未送出事件。");
      if (!Object.hasOwn(state.balances, action.author)) throw new Error("此身分不在測試網路中。");
      if (state.halted_authors.includes(action.author)) throw new Error("此身分有衝突，已暫停新事件。");
      const head = await request(`/authors/${encodeURIComponent(action.author)}/head`);
      if (head.halted) throw new Error("此身分有衝突，已暫停新事件。");
      const signed = await DirectionIdentity.signBrowserEvent(
        action.author, state.signature_domain, head, action.kind, action.payload);
      attemptedId = await DirectionIdentity.eventId(signed);
      rememberPendingAttempt(attemptedId);
      sendStarted = true;
      result = await request("/events", signed, 30000);
    } else {
      rememberPendingAttempt(null);
      sendStarted = true;
      result = await request("/actions", action, 30000);
    }
    if (!result || typeof result.accepted !== "boolean" ||
        typeof result.event !== "string" || !/^[0-9a-f]{64}$/.test(result.event))
      throw new Error("節點回覆缺少可核對的事件結果");
    if (attemptedId && result.event !== attemptedId)
      throw new Error("節點回覆的事件 ID 與本機簽章事件不符");
    responseAccepted = result.accepted;
    if (responseAccepted) {
      const record = await request(`/events/id/${result.event}`, undefined, 10000);
      const calculatedId = record.event ? await DirectionIdentity.eventId(record.event) : null;
      const browserValid = state.identity_mode !== "public-key" ||
        (Object.hasOwn(state.genesis, record.event?.author) &&
         await DirectionIdentity.verifyBrowserEvent(record.event, state.signature_domain));
      if (record.id !== result.event || calculatedId !== result.event ||
          record.signature_valid !== true || !browserValid)
        throw new Error("無法在本節點核對剛送出的簽章事件");
    }
    forgetPendingAttempt();
    let outcome = result.accepted ? `本機節點已接受事件：${result.event.slice(0, 12)}…` : `節點拒絕：${result.reason}`;
    if (result.accepted && result.relay) {
      const relay = result.relay;
      if (relay.failed.some(item => item.reason === "incompatible"))
        outcome += "；相鄰節點版本或網路配置不相容，事件尚未送達；請先確認兩端設定";
      else if (relay.failed.length) outcome += `；${relay.failed.length} 個相鄰節點未確認收到，請稍後同步`;
      else if (relay.suppressed) outcome += "；此節點未轉送該事件";
      else if (!relay.attempted) outcome += "；未設定相鄰節點，事件目前只在本機";
      else outcome += `；${relay.delivered.length} 個相鄰節點已回覆接收`;
    }
    try {
      await refresh();
      notice(outcome);
    } catch {
      notice(`${outcome}；但畫面無法更新，請確認節點狀態。`);
    }
    return Boolean(result.accepted);
  } catch (error) {
    if (sendStarted && (responseAccepted || !error.definitiveRejection)) {
      submissionUncertain = true;
      $("clear-uncertain").hidden = false;
      try { await refresh(); } catch { pauseNodeActions(); }
      if (attemptedId) {
        $("lookup-form").elements.event_id.value = attemptedId;
        if (nodeOnline) lookupById(attemptedId);
      }
      notice(`事件送出結果待確認：可能已寫入本機。${attemptedId ? `已填入簽章事件 ID ${attemptedId}，可查看本節點核對結果。` : ""}${pendingStorageAvailable ? "請核對事件清單後再重新載入頁面。" : "瀏覽器無法保存待確認標記；請勿重新載入本頁，先核對事件清單。"}不要直接重送。`);
      return false;
    }
    if (error.definitiveRejection) forgetPendingAttempt();
    notice(`操作失敗：${error.message}`);
    return false;
  } finally {
    submissionPending = false;
    if (!submissionUncertain && nodeOnline) refresh().catch(() => pauseNodeActions());
  }
}

$("transfer-form").addEventListener("submit", event => {
  event.preventDefault();
  const fields = new FormData(event.currentTarget);
  submit({author: fields.get("author"), kind: "transfer",
    payload: {recipient: fields.get("recipient"), amount: Number(fields.get("amount"))}});
});
$("transfer-form").elements.author.addEventListener("change", chooseDistinctRecipient);
$("proposal-form").addEventListener("submit", async event => {
  event.preventDefault();
  const fields = new FormData(event.currentTarget);
  const accepted = await submit({author: fields.get("author"), kind: "proposal",
    payload: {id: crypto.randomUUID(), title: String(fields.get("title")).trim()}});
  if (accepted) event.currentTarget.reset();
});
$("sync").addEventListener("click", async () => {
  if (!nodeOnline || syncPending) return;
  syncPending = true;
  $("sync").disabled = true;
  try {
    const report = await request("/sync", {});
    const unresolved = Object.values(report.unresolved || {}).reduce((total, items) => total + items.length, 0);
    const undelivered = Object.values(report.undelivered || {}).reduce((total, items) => total + items.length, 0);
    const deferred = Object.values(report.deferred || {}).reduce((total, count) => total + count, 0);
    const deferredRemote = Object.values(report.deferred_remote || {}).reduce((total, count) => total + count, 0);
    const problems = [];
    if (report.incompatible.length) problems.push(`${report.incompatible.length} 個網路配置不相容`);
    if (report.unreachable.length) problems.push(`${report.unreachable.length} 個節點無法連線`);
    if (report.invalid?.length) problems.push(`${report.invalid.length} 個節點回傳無效資料`);
    if (report.incomplete.length) problems.push(`${report.incomplete.length} 個節點事件快照不完整或正在變動`);
    if (unresolved) problems.push(`${unresolved} 個事件尚未解決`);
    if (undelivered) problems.push(`${undelivered} 個事件未送達`);
    if (deferred) problems.push(`${deferred} 個事件留待下次同步`);
    if (deferredRemote) problems.push(`${deferredRemote} 個相鄰節點事件留待下次匯入`);
    if (report.status?.balances_disputed) problems.push("本節點有未解決的衝突，暫定點數不可當作可用餘額");
    const outcome = problems.length
      ? `同步未完成：${problems.join("、")}；請檢查節點與衝突。`
      : "已完成一次同步檢查；事件仍屬暫定，尚無最終性。";
    try {
      await refresh();
      notice(outcome);
    } catch {
      notice(`${outcome}；但畫面無法更新，請確認節點狀態。`);
    }
  } catch (error) {
    try { await refresh(); } catch { pauseNodeActions(); }
    notice(`同步未完成：${error.message}。先前的部分事件可能已寫入本機；請核對事件數後重試。`);
  } finally {
    syncPending = false;
    $("sync").disabled = !nodeOnline || syncRunning || $("peer-count").textContent === "0";
  }
});
$("compare-peers").addEventListener("click", async () => {
  if (!nodeOnline || comparePending) return;
  comparePending = true;
  $("compare-peers").disabled = true;
  try {
    const report = await request("/compare");
    const differences = Object.values(report.differences);
    const onlyLocal = differences.reduce((total, item) => total + item.only_local.length, 0);
    const onlyRemote = differences.reduce((total, item) => total + item.only_remote.length, 0);
    const problems = [];
    if (report.unreachable.length) problems.push(`${report.unreachable.length} 個節點無法連線`);
    if (report.incompatible.length) problems.push(`${report.incompatible.length} 個網路配置不相容`);
    if (report.invalid.length) problems.push(`${report.invalid.length} 個節點事件無法驗證`);
    if (report.incomplete.length) problems.push(`${report.incomplete.length} 個節點快照不完整或正在變動`);
    if (report.local_changed) problems.push("本機事件在檢查期間變動，請重新檢查");
    if (onlyLocal) problems.push(`${onlyLocal} 筆只在本機`);
    if (onlyRemote) problems.push(`${onlyRemote} 筆只在相鄰節點`);
    if (report.balance_mismatch?.length) problems.push(`${report.balance_mismatch.length} 個相鄰節點的暫定點數不同`);
    if (report.proposal_mismatch?.length) problems.push(`${report.proposal_mismatch.length} 個相鄰節點的提案或票數不同`);
    notice(problems.length ? `節點比對發現問題：${problems.join("、")}。可同步缺少的事件；事件衝突不能靠同步裁決。`
      : "已連線的相鄰節點目前事件集合相同；這不是全網共識或最終結算證明。");
  } catch (error) { notice(`節點差異檢查失敗：${error.message}`); }
  finally {
    comparePending = false;
    $("compare-peers").disabled = !nodeOnline || $("peer-count").textContent === "0";
  }
});
for (const [buttonId, commandId] of [["copy-genesis-command", "genesis-command"],
                                      ["copy-pair-command", "pair-command"]]) {
  $(buttonId).addEventListener("click", async () => {
    const command = $(commandId).textContent;
    if ($(buttonId).disabled || !command.startsWith("python ")) return;
    if (!navigator.clipboard?.writeText) {
      notice("此瀏覽器無法複製命令；請手動選取畫面中的命令。");
      return;
    }
    try {
      await navigator.clipboard.writeText(command);
      notice("已複製啟動命令；請確認設定檔位置後在本機終端執行。");
    } catch {
      notice("複製命令失敗；請手動選取畫面中的命令。");
    }
  });
}
$("export-events").addEventListener("click", async () => {
  if (!nodeOnline || exportPending) return;
  exportPending = true;
  $("export-events").disabled = true;
  try {
    const state = await request("/status");
    const events = [];
    let cursor = 0;
    let snapshot = null;
    while (true) {
      const page = await request(`/snapshot/page?cursor=${cursor}&limit=128`);
      if (!Number.isSafeInteger(page.event_count) || !Number.isSafeInteger(page.relayable_count)
          || page.relayable_count < 0 || page.relayable_count > 10000
          || page.cursor !== cursor || !Array.isArray(page.events) || page.events.length > 128
          || (snapshot && (page.event_count !== snapshot.event_count
            || page.relayable_count !== snapshot.relayable_count
            || page.process_epoch !== snapshot.process_epoch
            || page.signature_domain !== snapshot.signature_domain
            || JSON.stringify(page.genesis) !== JSON.stringify(snapshot.genesis)))) {
        throw new Error("事件分頁不一致，請重試。");
      }
      if (!snapshot) snapshot = page;
      events.push(...page.events);
      if (page.next_cursor === null) break;
      if (!Number.isSafeInteger(page.next_cursor) || page.next_cursor !== cursor + page.events.length
          || page.next_cursor > page.relayable_count || page.events.length === 0)
        throw new Error("事件分頁游標無效，請重試。");
      cursor = page.next_cursor;
    }
    const stateAfter = await request("/status");
    if (state.events !== snapshot.event_count
        || state.signature_domain !== snapshot.signature_domain
        || state.process_epoch !== snapshot.process_epoch
        || JSON.stringify(state.genesis) !== JSON.stringify(snapshot.genesis)
        || events.length !== snapshot.relayable_count
        || stateAfter.events !== state.events
        || stateAfter.process_epoch !== state.process_epoch
        || stateAfter.signature_domain !== state.signature_domain
        || JSON.stringify(stateAfter.genesis) !== JSON.stringify(state.genesis)) {
      throw new Error("事件在下載時變動，請重試。");
    }
    const archive = {
      format: "direction-lab-local-events-v2",
      network_id: state.network_id,
      signature_domain: state.signature_domain,
      genesis: state.genesis,
      source_peer: state.peer,
      reported_event_count: state.events,
      finality: state.finality,
      events
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(archive, null, 2)], {type: "application/json"}));
    const anchor = document.createElement("a");
    anchor.href = url;
    const peerFileName = String(state.peer).replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 32) || "node";
    anchor.download = `direction-lab-${peerFileName}-local-events.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    const missing = snapshot.event_count - events.length;
    notice(missing > 0
      ? `已下載 ${events.length} 筆可轉送事件；另有 ${missing} 筆本機紀錄未納入，這不是完整備份。請勿視為最終結算證明。`
      : `已下載 ${events.length} 筆暫定事件；請自行保管，勿視為最終結算證明。`);
  } catch (error) {
    pauseNodeActions();
    notice(`下載事件紀錄失敗：${error.message}`);
  } finally {
    exportPending = false;
    $("export-events").disabled = !nodeOnline;
  }
});
$("create-identity").addEventListener("click", async () => {
  const button = $("create-identity");
  button.disabled = true;
  try {
    const id = await DirectionIdentity.createBrowserIdentity();
    notice(`已在此瀏覽器建立公鑰身分：${id.slice(0, 16)}…`);
    await refreshBrowserIdentities();
  } catch (error) { notice(`建立身分失敗：${error.message}`); }
  finally { button.disabled = false; }
});
$("genesis-command").textContent = "等待節點資訊…";
$("pair-command").textContent = "等待節點資訊…";
$("genesis-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const fields = new FormData(event.currentTarget);
    const ids = await DirectionIdentity.listBrowserIdentities();
    const genesis = DirectionIdentity.browserGenesis(
      ids, String(fields.get("network")), Number(fields.get("credits")), String(fields.get("additional_ids") || ""));
    const blob = new Blob([JSON.stringify(genesis, null, 2)], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "direction-lab-genesis.json";
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    notice("已下載只有公鑰與測試點數的網路設定；請依頁面步驟重啟節點。");
  } catch (error) { notice(`產生設定失敗：${error.message}`); }
});
$("clear-uncertain").addEventListener("click", async () => {
  const button = $("clear-uncertain");
  if (button.disabled) return;
  button.disabled = true;
  const attemptedId = pendingAttempt;
  try {
    const beforeReady = await refresh();
    if (!nodeOnline || !beforeReady) throw new Error("節點配置尚未核對");
    forgetPendingAttempt();
    submissionUncertain = false;
    const afterReady = await refresh();
    if (!nodeOnline || !afterReady) throw new Error("節點配置尚未核對");
    button.hidden = true;
    notice("已解除此頁送出暫停；請確認沒有重複建立同一筆測試事件。");
  } catch {
    rememberPendingAttempt(attemptedId);
    submissionUncertain = true;
    button.hidden = false;
    pauseNodeActions();
    notice("節點仍無法核對；送出結果待確認，交易與投票保持暫停。");
  } finally { button.disabled = false; }
});
refreshBrowserIdentities().catch(error => notice(`無法讀取本機身分：${error.message}`));
pauseNodeActions();
if (submissionUncertain) {
  $("clear-uncertain").hidden = false;
  notice("上一筆測試事件結果待確認；請先核對事件，再按解除暫停。不要直接重送。");
  if (/^[0-9a-f]{64}$/.test(pendingAttempt)) $("lookup-form").elements.event_id.value = pendingAttempt;
}
let pollInProgress = true;
refresh().then(() => {
  if (nodeOnline && /^[0-9a-f]{64}$/.test(pendingAttempt || "")) lookupById(pendingAttempt);
}).catch(error => notice(`無法讀取節點：${error.message}`))
  .finally(() => { pollInProgress = false; });
setInterval(() => {
  if (pollInProgress || submissionPending || syncPending) return;
  pollInProgress = true;
  refresh().catch(() => {}).finally(() => { pollInProgress = false; });
}, 3000);
