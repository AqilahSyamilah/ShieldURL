async function loadUsers() {
  const res = await fetch("../api/get_users.php", { credentials: "same-origin" });
  const users = await res.json();

  const container = document.getElementById("usersTable");
  if (!users || users.length === 0) {
    container.innerHTML = "<p>No users found.</p>";
    return;
  }

  let html = `<table border="1" cellpadding="6">
    <tr>
      <th>ID</th><th>Name</th><th>Username</th><th>Email</th>
      <th>Role</th><th>Active</th><th>Registered</th><th>Last Login</th>
    </tr>`;

  for (const u of users) {
    html += `<tr>
      <td>${u.id}</td>
      <td>${u.full_name ?? ""}</td>
      <td>${u.username}</td>
      <td>${u.email}</td>
      <td>${u.role}</td>
      <td>${u.is_active ? "Yes" : "No"}</td>
      <td>${u.registered_at ?? ""}</td>
      <td>${u.last_login ?? ""}</td>
    </tr>`;
  }

  html += "</table>";
  container.innerHTML = html;
}

document.getElementById("registerUserForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const form = e.target;
  const data = {
    full_name: form.full_name.value.trim(),
    username: form.username.value.trim(),
    email: form.email.value.trim(),
    password: form.password.value,
    phone: form.phone.value.trim() || null,
    department: form.department.value.trim() || null,
    role: form.role.value
  };

  const res = await fetch("../api/register_user.php", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(data)
  });

  const result = await res.json();
  const out = document.getElementById("registerResult");

  if (result.success) {
    out.innerHTML = `<p style="color:green;">${result.message}</p>`;
    form.reset();
    await loadUsers();
  } else {
    out.innerHTML = `<p style="color:red;">${result.error}</p>`;
  }
});

loadUsers();
