const promptEl = document.getElementById("prompt");
const sendBtn = document.getElementById("send");
const statusEl = document.getElementById("status");
const chatThread = document.getElementById("chatThread");
const emptyState = document.getElementById("emptyState");
const chatTitleEl = document.getElementById("chatTitle");
const newChatBtn = document.getElementById("newChat");
const historyListEl = document.getElementById("historyList");
const openDbBtn = document.getElementById("openDb");
const closeDbBtn = document.getElementById("closeDb");
const dbModal = document.getElementById("dbModal");
const dbAddForm = document.getElementById("dbAddForm");
const dbValueEl = document.getElementById("dbValue");
const dbTypeEl = document.getElementById("dbType");
const dbListEl = document.getElementById("dbList");

let currentSessionId = null;

// Friendly, plain-language names for technical entity types.
const TYPE_LABELS = {
  EMAIL: "Email address",
  PHONE_NUMBER: "Phone number",
  SSN: "Social Security Number",
  CREDIT_CARD: "Credit card number",
  IP_ADDRESS: "IP address",
  IBAN: "Bank account (IBAN)",
  BANK_ACCOUNT: "Bank account number",
  PASSPORT_NUMBER: "Passport number",
  DRIVERS_LICENSE: "Driver's license number",
  DATE_OF_BIRTH: "Date of birth",
  PERSON_NAME: "Name",
  ADDRESS: "Address",
  ORGANIZATION: "Organization",
  LOCATION: "Location",
  USERNAME: "Username",
  MAC_ADDRESS: "Device (MAC) address",
  VIN: "Vehicle ID number (VIN)",
  URL: "Web link (URL)",
  GEOLOCATION: "GPS coordinates",
  FAX_NUMBER: "Fax number",
  CREDIT_CARD_EXPIRATION: "Credit card expiration date",
  ZIP_CODE: "ZIP code",
  LICENSE_PLATE: "License plate number",
  MEDICAL_RECORD_NUMBER: "Medical record number",
  ICD_CODE: "Medical diagnosis code",
  NPI_NUMBER: "Provider ID (NPI)",
  HEALTH_INSURANCE_ID: "Health insurance ID",
  DEA_NUMBER: "DEA number",
  BILLING_ACCOUNT_NUMBER: "Billing account number",
  DATE_OF_SERVICE: "Medical service date",
  PATIENT_ID: "Patient ID",
  PROVIDER_LICENSE_NUMBER: "Provider license number",
  AWS_ACCESS_KEY: "AWS access key",
  AWS_SECRET_KEY: "AWS secret key",
  GCP_API_KEY: "Google Cloud API key",
  AZURE_CLIENT_SECRET: "Azure client secret",
  GITHUB_TOKEN: "GitHub access token",
  SLACK_TOKEN: "Slack access token",
  OPENAI_API_KEY: "OpenAI API key",
  ANTHROPIC_API_KEY: "Anthropic API key",
  JWT: "Login token (JWT)",
  PRIVATE_KEY: "Private encryption key",
  DB_CONNECTION_STRING: "Database connection details",
  GENERIC_API_KEY: "API key / access token",
  PASSWORD_ASSIGNMENT: "Password or secret",
};

// Friendly, plain-language descriptions of what was done with each entity.
const STRATEGY_LABELS = {
  TOKENIZE: "Hidden, restored in your reply",
  REDACT: "Removed completely",
  HASH: "Replaced with a code",
  PARTIAL_MASK: "Partially hidden",
  ALLOW: "Left as-is",
};

newChatBtn.addEventListener("click", startNewChat);
sendBtn.addEventListener("click", sendMessage);
promptEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

openDbBtn.addEventListener("click", openDbModal);
closeDbBtn.addEventListener("click", closeDbModal);
dbModal.addEventListener("click", (e) => {
  if (e.target === dbModal) closeDbModal();
});
dbAddForm.addEventListener("submit", handleDbAdd);

init();

async function init() {
  populateTypeOptions();
  await refreshHistory();
}

function populateTypeOptions() {
  dbTypeEl.innerHTML = "";
  const entries = Object.entries(TYPE_LABELS).sort((a, b) => a[1].localeCompare(b[1]));
  for (const [type, label] of entries) {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = label;
    dbTypeEl.appendChild(option);
  }
}

function startNewChat() {
  currentSessionId = null;
  chatTitleEl.textContent = "New chat";
  chatThread.innerHTML = "";
  chatThread.appendChild(emptyState);
  emptyState.hidden = false;
  statusEl.textContent = "";
  statusEl.classList.remove("error");
  promptEl.value = "";
  promptEl.focus();
  setActiveHistoryItem(null);
}

async function sendMessage() {
  const message = promptEl.value.trim();
  if (!message) return;

  emptyState.hidden = true;
  appendMessage({ role: "user", text: message });
  const pending = appendMessage({ role: "assistant", text: "Thinking…", pending: true });

  promptEl.value = "";
  sendBtn.disabled = true;
  sendBtn.classList.add("loading");
  statusEl.classList.remove("error");
  statusEl.textContent = "Checking your message and contacting the assistant…";

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, sessionId: currentSessionId }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || "Something went wrong. Please try again.");
    }

    const isNewSession = !currentSessionId;
    currentSessionId = data.sessionId;

    // Replace the "Thinking…" placeholder with the real reply + privacy details.
    pending.remove();
    appendMessage({
      role: "assistant",
      text: data.reconstructedResponse,
      maskedText: data.rawResponse,
    });

    // Attach privacy details to the user message we already rendered.
    attachUserPrivacyDetails(chatThread.lastElementChild?.previousElementSibling, {
      entities: data.entities,
      maskedText: data.sanitizedPrompt,
    });

    if (isNewSession) {
      chatTitleEl.textContent = data.title;
    }

    statusEl.textContent = "";
    await refreshHistory();
    setActiveHistoryItem(currentSessionId);
  } catch (err) {
    pending.remove();
    statusEl.classList.add("error");
    statusEl.textContent = err.message;
  } finally {
    sendBtn.disabled = false;
    sendBtn.classList.remove("loading");
    chatThread.scrollTop = chatThread.scrollHeight;
  }
}

/**
 * Renders a single chat bubble and returns its container element.
 */
function appendMessage({ role, text, pending, maskedText, entities }) {
  const wrapper = document.createElement("div");
  wrapper.className = `message ${role}${pending ? " pending" : ""}`;

  const bubble = document.createElement("div");
  bubble.className = "message-bubble";
  bubble.textContent = text;
  wrapper.appendChild(bubble);

  chatThread.appendChild(wrapper);
  chatThread.scrollTop = chatThread.scrollHeight;

  if (!pending) {
    if (role === "user" && entities) {
      attachUserPrivacyDetails(wrapper, { entities, maskedText });
    } else if (role === "assistant" && maskedText !== undefined) {
      attachAssistantPrivacyDetails(wrapper, { maskedText });
    }
  }

  return wrapper;
}

function attachUserPrivacyDetails(wrapper, { entities, maskedText }) {
  if (!wrapper || wrapper.querySelector(".privacy-toggle")) return;

  const count = entities ? entities.length : 0;
  const toggle = document.createElement("button");
  toggle.className = "privacy-toggle";
  toggle.innerHTML = `<span class="chevron">▶</span> ${
    count > 0 ? `${count} detail${count === 1 ? "" : "s"} protected` : "No personal details found"
  }`;

  const details = document.createElement("div");
  details.className = "privacy-details";

  const entitiesCard = document.createElement("div");
  entitiesCard.className = "privacy-card";
  entitiesCard.innerHTML = "<h4>What we protected</h4>";
  entitiesCard.appendChild(renderEntities(entities || []));
  details.appendChild(entitiesCard);

  const sanitizedCard = document.createElement("div");
  sanitizedCard.className = "privacy-card";
  sanitizedCard.innerHTML = "<h4>What the AI assistant saw</h4>";
  const sanitizedBox = document.createElement("pre");
  sanitizedBox.className = "content-box";
  sanitizedBox.textContent = maskedText || "";
  sanitizedCard.appendChild(sanitizedBox);
  details.appendChild(sanitizedCard);

  toggle.addEventListener("click", () => {
    toggle.classList.toggle("open");
    details.classList.toggle("open");
  });

  wrapper.appendChild(toggle);
  wrapper.appendChild(details);
}

function attachAssistantPrivacyDetails(wrapper, { maskedText }) {
  if (wrapper.querySelector(".privacy-toggle")) return;

  const toggle = document.createElement("button");
  toggle.className = "privacy-toggle";
  toggle.innerHTML = `<span class="chevron">▶</span> View raw reply from the AI`;

  const details = document.createElement("div");
  details.className = "privacy-details";

  const card = document.createElement("div");
  card.className = "privacy-card";
  card.innerHTML = "<h4>The AI's raw reply (before restoring your details)</h4>";
  const box = document.createElement("pre");
  box.className = "content-box";
  box.textContent = maskedText || "";
  card.appendChild(box);
  details.appendChild(card);

  toggle.addEventListener("click", () => {
    toggle.classList.toggle("open");
    details.classList.toggle("open");
  });

  wrapper.appendChild(toggle);
  wrapper.appendChild(details);
}

function renderEntities(entities) {
  const list = document.createElement("div");
  list.className = "entities-list";

  if (!entities.length) {
    const empty = document.createElement("p");
    empty.className = "entity-empty";
    empty.textContent = "Good news — we didn't find any personal details in this message.";
    list.appendChild(empty);
    return list;
  }

  for (const entity of entities) {
    const row = document.createElement("div");
    row.className = "entity-row";

    const info = document.createElement("div");
    info.className = "entity-info";

    const label = document.createElement("div");
    label.className = "entity-label";
    label.textContent = TYPE_LABELS[entity.type] || prettifyType(entity.type);

    const value = document.createElement("div");
    value.className = "entity-value";
    value.textContent = entity.value;

    info.appendChild(label);
    info.appendChild(value);

    const badge = document.createElement("span");
    badge.className = `badge ${entity.strategy}`;
    badge.textContent = STRATEGY_LABELS[entity.strategy] || entity.strategy;

    row.appendChild(info);

    if (entity.source === "dictionary") {
      const dbBadge = document.createElement("span");
      dbBadge.className = "badge dictionary-source";
      dbBadge.textContent = "From your privacy database";
      row.appendChild(dbBadge);
    } else {
      const addBtn = document.createElement("button");
      addBtn.className = "entity-add-btn";
      addBtn.textContent = "+ Always hide this";
      addBtn.addEventListener("click", () => addToDatabase(entity.value, entity.type, addBtn));
      row.appendChild(addBtn);
    }

    row.appendChild(badge);
    list.appendChild(row);
  }

  return list;
}

function prettifyType(type) {
  return type
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// ---------------------------------------------------------------------------
// Chat history sidebar
// ---------------------------------------------------------------------------

async function refreshHistory() {
  try {
    const res = await fetch("/api/sessions");
    if (!res.ok) return;
    const sessions = await res.json();
    renderHistory(sessions);
  } catch {
    // Non-fatal: history sidebar simply stays empty.
  }
}

function renderHistory(sessions) {
  historyListEl.innerHTML = "";

  if (!sessions.length) {
    const empty = document.createElement("p");
    empty.className = "history-empty";
    empty.textContent = "Your past conversations will appear here.";
    historyListEl.appendChild(empty);
    return;
  }

  for (const session of sessions) {
    const item = document.createElement("div");
    item.className = "history-item";
    item.dataset.sessionId = session.id;
    if (session.id === currentSessionId) item.classList.add("active");

    const title = document.createElement("span");
    title.className = "history-title";
    title.textContent = session.title;

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "history-delete";
    deleteBtn.setAttribute("aria-label", "Delete conversation");
    deleteBtn.textContent = "✕";
    deleteBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteSession(session.id);
    });

    item.appendChild(title);
    item.appendChild(deleteBtn);
    item.addEventListener("click", () => loadSession(session.id));
    historyListEl.appendChild(item);
  }
}

function setActiveHistoryItem(sessionId) {
  for (const item of historyListEl.querySelectorAll(".history-item")) {
    item.classList.toggle("active", item.dataset.sessionId === sessionId);
  }
}

async function loadSession(sessionId) {
  if (sessionId === currentSessionId) return;

  try {
    const res = await fetch(`/api/sessions/${sessionId}`);
    if (!res.ok) throw new Error("Could not load that conversation.");
    const session = await res.json();

    currentSessionId = session.id;
    chatTitleEl.textContent = session.title;
    chatThread.innerHTML = "";
    emptyState.hidden = true;

    for (const message of session.messages) {
      appendMessage({
        role: message.role,
        text: message.text,
        maskedText: message.maskedText,
        entities: message.entities,
      });
    }

    statusEl.textContent = "";
    statusEl.classList.remove("error");
    setActiveHistoryItem(sessionId);
  } catch (err) {
    statusEl.classList.add("error");
    statusEl.textContent = err.message;
  }
}

async function deleteSession(sessionId) {
  try {
    await fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
    if (sessionId === currentSessionId) {
      startNewChat();
    }
    await refreshHistory();
  } catch {
    // Non-fatal.
  }
}

// ---------------------------------------------------------------------------
// Privacy database (deterministic, exact-match known values)
// ---------------------------------------------------------------------------

async function openDbModal() {
  dbModal.hidden = false;
  await refreshDb();
  dbValueEl.focus();
}

function closeDbModal() {
  dbModal.hidden = true;
}

async function refreshDb() {
  try {
    const res = await fetch("/api/known-entities");
    if (!res.ok) return;
    const entries = await res.json();
    renderDb(entries);
  } catch {
    // Non-fatal.
  }
}

function renderDb(entries) {
  dbListEl.innerHTML = "";

  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "entity-empty";
    empty.textContent = "Your privacy database is empty.";
    dbListEl.appendChild(empty);
    return;
  }

  for (const entry of entries) {
    const row = document.createElement("div");
    row.className = "entity-row";

    const info = document.createElement("div");
    info.className = "entity-info";

    const label = document.createElement("div");
    label.className = "entity-label";
    label.textContent = TYPE_LABELS[entry.type] || prettifyType(entry.type);

    const value = document.createElement("div");
    value.className = "entity-value";
    value.textContent = entry.value;

    info.appendChild(label);
    info.appendChild(value);

    const removeBtn = document.createElement("button");
    removeBtn.className = "entity-add-btn";
    removeBtn.textContent = "Remove";
    removeBtn.addEventListener("click", () => removeFromDatabase(entry.value, entry.type));

    row.appendChild(info);
    row.appendChild(removeBtn);
    dbListEl.appendChild(row);
  }
}

async function handleDbAdd(e) {
  e.preventDefault();
  const value = dbValueEl.value.trim();
  const type = dbTypeEl.value;
  if (!value || !type) return;

  await fetch("/api/known-entities", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value, type }),
  });

  dbValueEl.value = "";
  await refreshDb();
}

async function addToDatabase(value, type, button) {
  button.disabled = true;
  button.textContent = "Added";
  await fetch("/api/known-entities", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value, type }),
  });
}

async function removeFromDatabase(value, type) {
  await fetch("/api/known-entities", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value, type }),
  });
  await refreshDb();
}
