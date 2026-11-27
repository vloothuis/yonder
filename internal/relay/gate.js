(function () {
  const msg = document.getElementById('msg');
  const form = document.getElementById('f');

  async function submit(code) {
    msg.textContent = 'Checking the code…';
    const slow = setTimeout(() => { msg.textContent = 'Waiting for the owner to let you in…'; }, 800);
    try {
      const res = await fetch('/_yonder/auth', {
        method: 'POST',
        body: new URLSearchParams({ code }),
        credentials: 'same-origin',
      });
      clearTimeout(slow);
      if (res.ok) { location.reload(); return; }
      msg.textContent = (await res.text()).trim() || 'Access refused.';
    } catch (e) {
      clearTimeout(slow);
      msg.textContent = 'The share could not be reached.';
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    submit(form.code.value.trim());
  });

  const m = location.hash.match(/[#&]c=([^&]+)/);
  if (m) {
    history.replaceState(null, '', location.pathname + location.search);
    submit(decodeURIComponent(m[1]));
  }
})();
