async function parseJsonResponse(response) {
  const text = await response.text();
  console.log("Raw response:", text);

  let data = null;
  if (text.trim() !== "") {
    try {
      data = JSON.parse(text);
    } catch (error) {
      throw new Error("Backend did not return valid JSON: " + text);
    }
  }

  if (!response.ok) {
    throw new Error(
      (data && (data.error || data.detail || data.message)) ||
      ("Request failed with status " + response.status)
    );
  }

  return data;
}

async function loadUsers() {
  const res = await fetch("../api/get_users.php", { credentials: "same-origin" });
  const users = await parseJsonResponse(res);

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
    email: form.email.value.trim(),
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

  const result = await parseJsonResponse(res);
  const out = document.getElementById("registerResult");

  if (result.success) {
    out.textContent = result.message;
    out.style.color = "green";
    form.reset();
    await loadUsers();
  } else {
    out.textContent = result.message || "Registration failed";
    out.style.color = "red";
  }
});

loadUsers();
