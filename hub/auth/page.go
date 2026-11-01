package auth

const loginPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<script>
  (function () {
    var theme = new URLSearchParams(location.search).get('theme');
    if (theme === 'light' || theme === 'dark') {
      document.documentElement.dataset.theme = theme;
    }
  })();
</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in</title>
<style>
:root {
  color-scheme: light;
  --bg: #f2f4f7;
  --fg: #1b1f24;
  --card: #ffffff;
  --muted: #5b6573;
  --line: #d4d9e1;
  --input-bg: #ffffff;
  --accent: #2563eb;
  --shadow: rgba(15, 23, 42, .12);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif;
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0f1115;
  --fg: #e8eaed;
  --card: #181b21;
  --muted: #9aa4b2;
  --line: #333a45;
  --input-bg: #0f1115;
  --accent: #60a5fa;
  --shadow: rgba(0, 0, 0, .5);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme]) {
    color-scheme: dark;
    --bg: #0f1115;
    --fg: #e8eaed;
    --card: #181b21;
    --muted: #9aa4b2;
    --line: #333a45;
    --input-bg: #0f1115;
    --accent: #60a5fa;
    --shadow: rgba(0, 0, 0, .5);
  }
}
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg); color: var(--fg); }
.card { width: min(420px, calc(100vw - 32px)); background: var(--card); border-radius: 18px; padding: 24px; box-shadow: 0 12px 40px var(--shadow); }
h1 { font-size: 20px; margin: 0 0 8px; }
p { margin: 0 0 16px; color: var(--muted); line-height: 1.5; }
label { display: block; font-size: 13px; color: var(--muted); margin: 12px 0 6px; }
input { width: 100%; box-sizing: border-box; padding: 11px 12px; border: 1px solid var(--line); border-radius: 10px; font-size: 15px; background: var(--input-bg); color: var(--fg); }
button { width: 100%; margin-top: 18px; padding: 12px; border: 0; border-radius: 10px; background: var(--accent); color: #fff; font-size: 15px; font-weight: 600; cursor: pointer; }
button:disabled { opacity: .55; cursor: default; }
.captcha-wrap { position: relative; display: inline-block; margin: 8px 0; touch-action: manipulation; }
.captcha-wrap img { display: block; max-width: 100%; border-radius: 10px; cursor: crosshair; user-select: none; }
.mark { position: absolute; width: 22px; height: 22px; margin: -11px 0 0 -11px; border-radius: 50%; border: 2px solid #ef4444; color: #ef4444; font-size: 12px; line-height: 18px; text-align: center; font-weight: 700; pointer-events: none; background: rgba(255,255,255,.75); }
.hint { font-size: 13px; color: var(--muted); margin-top: 4px; }
.error { color: #b91c1c; white-space: pre-wrap; margin-top: 12px; font-size: 14px; }
.success { color: #15803d; font-size: 16px; margin: 8px 0 0; }
a { color: var(--accent); }
</style>
</head>
<body>
<div class="card">
  <h1 id="title">Sign-in</h1>
  <p id="description">Loading sign-in status…</p>
  <form id="form" novalidate></form>
  <div id="error" class="error"></div>
</div>
<script>
(function () {
  var id = location.pathname.split('/').pop();
  var nonce = new URLSearchParams(location.search).get('t') || '';
  var state = null;
  var points = [];
  var submitting = false;
  var renderedStepId = null;
  var title = document.getElementById('title');
  var description = document.getElementById('description');
  var form = document.getElementById('form');
  var errorBox = document.getElementById('error');

  function headers() {
    return { 'Content-Type': 'application/json', 'X-Auth-Nonce': nonce };
  }

  function request(path, options) {
    options = options || {};
    options.headers = Object.assign(headers(), options.headers || {});
    return fetch(path, options).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        if (!response.ok) {
          var message = body && body.error ? body.error.message : response.statusText;
          throw new Error(message || ('HTTP ' + response.status));
        }
        return body;
      });
    });
  }

  function el(tag, props, children) {
    var node = document.createElement(tag);
    Object.keys(props || {}).forEach(function (key) {
      if (key === 'text') { node.textContent = props[key]; }
      else if (key === 'className') { node.className = props[key]; }
      else if (key.indexOf('on') === 0) { node.addEventListener(key.slice(2), props[key]); }
      else { node.setAttribute(key, props[key]); }
    });
    (children || []).forEach(function (child) { if (child) node.appendChild(child); });
    return node;
  }

  function renderStep(step, force) {
    if (!step) { return; }
    if (!force && step.id === renderedStepId) { return; }
    renderedStepId = step.id;
    form.innerHTML = '';
    points = [];
    if (!step) { return; }
    title.textContent = step.title || 'Sign-in';
    description.textContent = step.description || '';
    if (step.type === 'captcha' && step.image) {
      var wrap = el('div', { className: 'captcha-wrap' });
      var image = el('img', { src: step.image, alt: 'Click verification' });
      var hint = el('div', { className: 'hint', text: 'Click the characters in the order shown.' });
      var markerLayer = [];
      image.addEventListener('click', function (event) {
        var rect = image.getBoundingClientRect();
        var x = Math.round((event.clientX - rect.left) * image.naturalWidth / rect.width);
        var y = Math.round((event.clientY - rect.top) * image.naturalHeight / rect.height);
        points.push([x, y]);
        var mark = el('span', { className: 'mark', text: String(points.length) });
        mark.style.left = (event.clientX - rect.left) + 'px';
        mark.style.top = (event.clientY - rect.top) + 'px';
        wrap.appendChild(mark);
        markerLayer.push(mark);
      });
      wrap.appendChild(image);
      form.appendChild(wrap);
      form.appendChild(hint);
      var clear = el('button', { type: 'button', text: 'Clear selection', onclick: function () {
        points = [];
        markerLayer.forEach(function (mark) { mark.remove(); });
        markerLayer = [];
      }});
      clear.style.background = '#64748b';
      form.appendChild(clear);
    } else {
      (step.fields || []).forEach(function (field) {
        if (field.type === 'hidden') { return; }
        form.appendChild(el('label', { for: 'field-' + field.name, text: field.label || field.name }));
        var input = el('input', {
          id: 'field-' + field.name,
          type: field.type === 'password' ? 'password' : (field.type === 'code' ? 'text' : 'text'),
          inputmode: field.type === 'code' ? 'numeric' : 'text',
          autocomplete: field.name === 'username' ? 'username' : (field.type === 'password' ? 'current-password' : 'one-time-code'),
          placeholder: field.placeholder || '',
          value: field.value || '',
          'data-name': field.name
        });
        form.appendChild(input);
      });
    }
    var submit = el('button', { type: 'submit', text: step.type === 'confirm' ? 'Confirm' : 'Submit' });
    submit.disabled = submitting;
    form.appendChild(submit);
  }

  function collect(step) {
    var values = {};
    (step.fields || []).forEach(function (field) {
      if (field.type === 'click') { values[field.name] = points; return; }
      var input = document.getElementById('field-' + field.name);
      if (input) { values[field.name] = input.value; }
    });
    return values;
  }

  function render(snapshot) {
    state = snapshot;
    errorBox.textContent = snapshot.error || '';
    if (snapshot.state === 'succeeded') {
      title.textContent = 'Sign-in complete';
      description.textContent = 'You can close this page and return to the client.';
      form.innerHTML = '<p class="success">aTrust session established.</p>';
      return;
    }
    if (snapshot.state === 'failed' || snapshot.state === 'cancelled') {
      title.textContent = 'Sign-in failed';
      description.textContent = 'Return to the client and start sign-in again.';
      form.innerHTML = '';
      return;
    }
    if (snapshot.state === 'awaiting_input' && snapshot.step) {
      renderStep(snapshot.step);
      return;
    }
    title.textContent = 'Signing in…';
    description.textContent = 'Contacting the authentication service.';
    form.innerHTML = '';
  }

  function load() {
    request('/auth/v1/sessions/' + encodeURIComponent(id)).then(render).catch(function (error) {
      errorBox.textContent = error.message;
    });
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (!state || !state.step || submitting) { return; }
    submitting = true;
    var button = form.querySelector('button[type="submit"]');
    if (button) { button.disabled = true; button.textContent = 'Submitting…'; }
    request('/auth/v1/sessions/' + encodeURIComponent(id) + '/submit', {
      method: 'POST',
      body: JSON.stringify({ step_id: state.step.id, values: collect(state.step) })
    }).then(function (snapshot) {
      submitting = false;
      render(snapshot);
      if (snapshot.state === 'awaiting_input') { return; }
    }).catch(function (error) {
      submitting = false;
      errorBox.textContent = error.message;
      renderStep(state.step, true);
    });
  });

  load();
  setInterval(function () {
    if (state && (state.state === 'pending' || state.state === 'awaiting_input')) {
      load();
    }
  }, 1500);
})();
</script>
</body>
</html>
`
