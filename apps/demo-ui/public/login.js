const tabs = document.querySelectorAll(".auth-tab");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const loginError = document.getElementById("loginError");
const regError = document.getElementById("regError");
const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");

// Redirect already-authenticated users straight to the app.
(async () => {
  try {
    const res = await fetch("/api/auth/me");
    if (res.ok) window.location.replace("/");
  } catch {
    // ignore — just show the login page
  }
})();

// Tab switching
tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => {
      t.classList.remove("active");
      t.setAttribute("aria-selected", "false");
    });
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    const which = tab.dataset.tab;
    loginForm.hidden = which !== "login";
    registerForm.hidden = which !== "register";
    loginError.hidden = true;
    regError.hidden = true;
  });
});

function setLoading(btn, loading) {
  btn.disabled = loading;
  btn.classList.toggle("loading", loading);
}

function showError(el, message) {
  el.textContent = message;
  el.hidden = false;
}

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  loginError.hidden = true;
  setLoading(loginBtn, true);
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("loginUsername").value.trim(),
        password: document.getElementById("loginPassword").value,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Login failed.");
    window.location.replace("/");
  } catch (err) {
    showError(loginError, err.message);
    setLoading(loginBtn, false);
  }
});

registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  regError.hidden = true;
  setLoading(registerBtn, true);
  try {
    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("regUsername").value.trim(),
        password: document.getElementById("regPassword").value,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Registration failed.");
    window.location.replace("/");
  } catch (err) {
    showError(regError, err.message);
    setLoading(registerBtn, false);
  }
});
