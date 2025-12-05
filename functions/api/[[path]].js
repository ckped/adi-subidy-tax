// functions/api/[[path]].js

// ===== CORS（同網域其實不太需要，但保留） =====
const ALLOWED_ORIGINS = [
  "http://localhost:8000",
  "http://127.0.0.1:8000",
  "http://127.0.0.1:8789",
  "https://adi-subsidy.pages.dev",
  "https://inv-subsidy-adi.pages.dev",
];

const ADMIN_EMAILS = [
  "enyichen0413@adi.gov.tw", // 先放你自己，之後可再加其他管理者
];

function isAdmin(email) {
  return ADMIN_EMAILS.includes(email);
}

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin);
  return {
    "Access-Control-Allow-Origin": allowed ? origin : "",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Credentials": "true",
  };
}

function withCors(request, response) {
  const headers = new Headers(response.headers);
  const cors = getCorsHeaders(request);
  for (const [k, v] of Object.entries(cors)) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/** 取得使用者 email：
 *  - 正式：Cf-Access-Authenticated-User-Email
 *  - 本地 dev：X-User-Email（只有沒有 Access header 時才用）
 */
function getEmail(request) {
  const access =
    request.headers.get("Cf-Access-Authenticated-User-Email") || "";
  const dev = request.headers.get("X-User-Email") || "";
  return access || dev || "";
}
/** 單行 CSV 解析：支援雙引號與逗點，例如 "850,000" */
function parseCsvLine(line) {
  const cells = [];
  let cur = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const c = line[i];

    if (inQuotes) {
      if (c === '"') {
        // 連續兩個 "" -> 代表字串中的一個 "
        if (i + 1 < line.length && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += c;
      }
    } else {
      if (c === '"') {
        inQuotes = true;
      } else if (c === ",") {
        cells.push(cur);
        cur = "";
      } else {
        cur += c;
      }
    }
  }

  cells.push(cur);
  return cells;
}

/** 安全包裝資料表/欄位名稱，支援中文欄位名 */
function quoteIdent(name) {
  const escaped = name.replace(/"/g, '""');
  return `"${escaped}"`;
}

/** 解析 /api/services/:id/delete */
function matchServiceDeletePath(pathname) {
  const m = pathname.match(/^\/api\/services\/(\d+)\/delete$/);
  if (!m) return null;
  return parseInt(m[1], 10);
}


/** 解析 /api/services/:id/upload */
function matchUploadPath(pathname) {
  const m = pathname.match(/^\/api\/services\/(\d+)\/upload$/);
  if (!m) return null;
  return parseInt(m[1], 10);
}

/** 解析 /api/services/:id/uploads */
function matchServiceUploadsPath(pathname) {
  const m = pathname.match(/^\/api\/services\/(\d+)\/uploads$/);
  if (!m) return null;
  return parseInt(m[1], 10);
}

/** 解析 /api/services/:serviceId/uploads/:uploadId/delete */
function matchUploadDeletePath(pathname) {
  const m = pathname.match(/^\/api\/services\/\d+\/uploads\/(\d+)\/delete$/);
  if (!m) return null;
  return parseInt(m[1], 10);
}

/** 解析 /api/services/:id/transfer-owner */
function matchServiceTransferOwnerPath(pathname) {
  const m = pathname.match(/^\/api\/services\/(\d+)\/transfer-owner$/);
  if (!m) return null;
  return parseInt(m[1], 10);
}

/** 統一 JSON 回應 */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

// ==========================
// Pages Functions 入口
// ==========================
export const onRequest = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);
  const { pathname } = url;

  // CORS 預檢
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: getCorsHeaders(request),
    });
  }

  const email = getEmail(request);

  try {
    // 健康檢查
    if (pathname === "/") {
      return withCors(
        request,
        new Response(
          "OK: adi-invest-platform Pages Functions is running",
          { status: 200 }
        )
      );
    }

    // 認證與使用者
    if (pathname === "/api/me" && request.method === "GET") {
      return withCors(request, await handleMe(env, email));
    }

    // 服務項目列表 / 建立
    if (pathname === "/api/services" && request.method === "GET") {
      return withCors(request, await handleListServices(env, email, url));
    }
    if (pathname === "/api/services" && request.method === "POST") {
      return withCors(
        request,
        await handleCreateService(request, env, email)
      );
    }
    // 服務項目刪除
    const serviceIdForDeleteService = matchServiceDeletePath(pathname);
    if (serviceIdForDeleteService !== null && request.method === "POST") {
      return withCors(
        request,
        await handleDeleteService(env, email, serviceIdForDeleteService)
      );
    }


    // 上傳資料
    const serviceIdForUpload = matchUploadPath(pathname);
    if (serviceIdForUpload !== null && request.method === "POST") {
      return withCors(
        request,
        await handleUploadServiceData(
          request,
          env,
          email,
          serviceIdForUpload
        )
      );
    }

    // 服務的上傳紀錄列表
    const serviceIdForUploads = matchServiceUploadsPath(pathname);
    if (serviceIdForUploads !== null && request.method === "GET") {
      return withCors(
        request,
        await handleListServiceUploads(env, email, serviceIdForUploads, url)
      );
    }

    // 刪除某一次上傳
    const uploadIdForDelete = matchUploadDeletePath(pathname);
    if (uploadIdForDelete !== null && request.method === "POST") {
      return withCors(
        request,
        await handleDeleteUpload(env, email, uploadIdForDelete)
      );
    }

    // 轉移服務負責人
    const serviceIdForTransfer = matchServiceTransferOwnerPath(pathname);
    if (serviceIdForTransfer !== null && request.method === "POST") {
      return withCors(
        request,
        await handleTransferServiceOwner(
          request,
          env,
          email,
          serviceIdForTransfer
        )
      );
    }

    // 查詢 API
    if (pathname === "/api/search" && request.method === "GET") {
      return withCors(request, await handleSearch(env, email, url));
    }

    // 匯出 CSV
    if (pathname === "/api/search/export" && request.method === "GET") {
      return withCors(
        request,
        await handleSearchExport(env, email, url)
      );
    }

    return withCors(request, new Response("Not found", { status: 404 }));
  } catch (err) {
    console.error("Unhandled error", err);
    return withCors(
      request,
      json(
        {
          error: "Internal Error",
          message: String(err && err.message ? err.message : err),
          stack: err && err.stack ? err.stack : null,
        },
        500
      )
    );
  }
};

// ========== handlers: user & services ==========

async function handleMe(env, email) {
  if (!email) return json({ authenticated: false }, 401);

  const db = env.DB;

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        display_name TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );
    `)
    .run();

  let user = await db
    .prepare(
      "SELECT email, display_name, created_at FROM users WHERE email = ?"
    )
    .bind(email)
    .first();

  if (!user) {
    await db
      .prepare("INSERT INTO users (email, display_name) VALUES (?, ?)")
      .bind(email, email.split("@")[0])
      .run();

    user = await db
      .prepare(
        "SELECT email, display_name, created_at FROM users WHERE email = ?"
      )
      .bind(email)
      .first();
  }

  return json({ authenticated: true, user });
}

async function handleListServices(env, email, url) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const mine = url.searchParams.get("mine") === "1";
  const db = env.DB;

  let query = "SELECT * FROM service_items";
  const params = [];

  if (mine) {
    query += " WHERE owner_email = ?";
    params.push(email);
  }

  const result = await db.prepare(query).bind(...params).all();
  return json(result.results || []);
}


async function handleCreateService(request, env, email) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const body = await request.json();
  const name = body.name ? body.name.trim() : "";
  const description = body.description ? body.description.trim() : "";

  if (!name) return json({ error: "name is required" }, 400);

  const db = env.DB;

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS service_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        table_name TEXT UNIQUE NOT NULL,
        owner_email TEXT NOT NULL,
        created_by_email TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT
      );
    `)
    .run();

  const insertResult = await db
    .prepare(
      "INSERT INTO service_items (name, description, table_name, owner_email, created_by_email) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(name, description, "temp", email, email)
    .run();

  const serviceId = insertResult.meta.last_row_id;
  const tableName = `service_${serviceId}_data`;

  await db
    .prepare("UPDATE service_items SET table_name = ? WHERE id = ?")
    .bind(tableName, serviceId)
    .run();

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        upload_id INTEGER NOT NULL
      );
    `)
    .run();

  const service = await db
    .prepare("SELECT * FROM service_items WHERE id = ?")
    .bind(serviceId)
    .first();

  return json(service, 201);
}

async function handleDeleteService(env, email, serviceId) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const db = env.DB;

  // 確保相關表存在（如果你已經有 ensureServiceItemsTable/ensureUploadsTable，就改成呼叫它們）
  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS service_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        table_name TEXT UNIQUE NOT NULL,
        owner_email TEXT NOT NULL,
        created_by_email TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT
      );
    `)
    .run();

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER NOT NULL,
        original_filename TEXT,
        header_row_index INTEGER NOT NULL,
        uploaded_by_email TEXT NOT NULL,
        uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
        row_count INTEGER,
        company_id_header TEXT,
        company_name_header TEXT,
        status TEXT DEFAULT 'active',
        deleted_at TEXT,
        FOREIGN KEY (service_id) REFERENCES service_items(id),
        FOREIGN KEY (uploaded_by_email) REFERENCES users(email)
      );
    `)
    .run();

  // 先查 service
  const service = await db
    .prepare("SELECT * FROM service_items WHERE id = ?")
    .bind(serviceId)
    .first();

  if (!service) {
    return json({ error: "Service not found" }, 404);
  }

  const isOwner = service.owner_email === email;

  // 僅允許：管理端 或 現任 owner
  if (!isAdmin(email) && !isOwner) {
    return json({
      error: "Forbidden: only admin or current owner can delete service",
    }, 403);
  }

  const tableName = service.table_name;

  // 刪除該 service 的所有 uploads 紀錄
  await db
    .prepare("DELETE FROM uploads WHERE service_id = ?")
    .bind(serviceId)
    .run();

  // 刪除該 service 對應的資料表（service_X_data）
  if (tableName) {
    try {
      await db
        .prepare(`DROP TABLE IF EXISTS ${tableName};`)
        .run();
    } catch (e) {
      console.error("DROP TABLE failed:", tableName, e);
      // 這裡失敗就 log，照你需求可選擇要不要 return error
    }
  }

  // 最後刪掉 service_items 這一筆
  await db
    .prepare("DELETE FROM service_items WHERE id = ?")
    .bind(serviceId)
    .run();

  return json({ success: true, deleted_service_id: serviceId });
}


// ========== 上傳 API ==========

async function handleUploadServiceData(request, env, email, serviceId) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const body = await request.json();
  if (!body || !body.data) {
    return json({ error: "data (CSV text) is required" }, 400);
  }

  const filename = body.filename || null;
  const headerRow = body.header_row != null ? body.header_row : 2;
  const companyIdHeader = body.company_id_header || "統一編號";
  const companyNameHeader = body.company_name_header || "公司名稱";

  const db = env.DB;

  const service = await db
    .prepare("SELECT * FROM service_items WHERE id = ?")
    .bind(serviceId)
    .first();
  if (!service) return json({ error: "Service not found" }, 404);

  const tableName = service.table_name;

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        upload_id INTEGER NOT NULL
      );
    `)
    .run();

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER NOT NULL,
        original_filename TEXT,
        header_row_index INTEGER NOT NULL,
        uploaded_by_email TEXT NOT NULL,
        uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
        row_count INTEGER,
        company_id_header TEXT,
        company_name_header TEXT,
        status TEXT DEFAULT 'active',
        deleted_at TEXT,
        FOREIGN KEY (service_id) REFERENCES service_items(id),
        FOREIGN KEY (uploaded_by_email) REFERENCES users(email)
      );
    `)
    .run();

  const lines = body.data
    .split(/\r?\n/)
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0);

  if (lines.length < headerRow) {
    return json(
      { error: `header_row=${headerRow} is beyond total lines=${lines.length}` },
      400
    );
  }

  const headerLine = lines[headerRow - 1];
  const headersRaw = parseCsvLine(headerLine).map((h) => h.trim());

  const idxCompanyId = headersRaw.findIndex((h) => h === companyIdHeader);
  const idxCompanyName = headersRaw.findIndex((h) => h === companyNameHeader);

  if (idxCompanyId === -1 || idxCompanyName === -1) {
    return json(
      {
        error: "Missing company_id_header or company_name_header in CSV header",
        headers: headersRaw,
        company_id_header: companyIdHeader,
        company_name_header: companyNameHeader,
      },
      400
    );
  }

  const dataLines = lines.slice(headerRow);

  for (const h of headersRaw) {
    try {
      await db
        .prepare(`ALTER TABLE ${tableName} ADD COLUMN ${quoteIdent(h)} TEXT;`)
        .run();
    } catch (e) {
      const msg = String(e && e.message ? e.message : e);
      if (msg.includes("duplicate column name")) continue;
      throw e;
    }
  }

  const uploadInsert = await db
    .prepare(
      `
      INSERT INTO uploads (
        service_id,
        original_filename,
        header_row_index,
        uploaded_by_email,
        row_count,
        company_id_header,
        company_name_header,
        status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    `
    )
    .bind(
      serviceId,
      filename,
      headerRow,
      email,
      0,
      companyIdHeader,
      companyNameHeader,
      "active"
    )
    .run();

  const uploadId = uploadInsert.meta.last_row_id;

  const columnIdents = headersRaw.map((h) => quoteIdent(h)).concat(`"upload_id"`);
  const placeholders = headersRaw.map(() => "?").concat("?").join(",");
  const insertSQL = `INSERT INTO ${tableName} (${columnIdents.join(
    ","
  )}) VALUES (${placeholders});`;

  let inserted = 0;

  for (const line of dataLines) {
    const cells = parseCsvLine(line);

    const companyId = (cells[idxCompanyId] || "").trim();
    const companyName = (cells[idxCompanyName] || "").trim();
    if (!companyId && !companyName) continue;

    const values = [];
    for (let i = 0; i < headersRaw.length; i++) {
      values.push(cells[i] != null ? cells[i] : "");
    }
    values.push(uploadId);

    await db.prepare(insertSQL).bind(...values).run();
    inserted += 1;
  }

  await db
    .prepare("UPDATE uploads SET row_count = ? WHERE id = ?")
    .bind(inserted, uploadId)
    .run();

  return json({
    service_id: serviceId,
    table_name: tableName,
    upload_id: uploadId,
    inserted_rows: inserted,
    header_row: headerRow,
    headers: headersRaw,
    company_id_header: companyIdHeader,
    company_name_header: companyNameHeader,
  });
}

// ========== 查詢 + 匯出 API ==========

async function searchAll(env, q) {
  const db = env.DB;
  const isCompanyId = /^\d{8}$/.test(q);

  // 1. 抓所有服務項目
  const servicesRes = await db
    .prepare("SELECT id, name, table_name FROM service_items;")
    .all();
  const services = servicesRes.results || [];

  const items = [];

  for (const svc of services) {
    const serviceId = svc.id;
    const serviceName = svc.name;
    const tableName = svc.table_name;

    // 2. 抓這個 service 下面所有「還是 active 的上傳紀錄」
    const uploadsRes = await db
      .prepare(
        `
        SELECT *
        FROM uploads
        WHERE service_id = ? AND status = 'active'
        ORDER BY uploaded_at DESC, id DESC;
      `
      )
      .bind(serviceId)
      .all();

    const uploads = uploadsRes.results || [];
    if (!uploads.length) continue;

    // 3. 對每一個 upload_id 各查一次
    for (const upload of uploads) {
      const uploadId = upload.id;

      const companyIdHeader = upload.company_id_header || "統一編號";
      const companyNameHeader = upload.company_name_header || "公司名稱";

      const companyIdCol = quoteIdent(companyIdHeader);
      const companyNameCol = quoteIdent(companyNameHeader);

      let sql;
      let params;

      if (isCompanyId) {
        // 統編精準 + 限縮在這次上傳
        sql = `SELECT * FROM ${tableName} WHERE upload_id = ? AND ${companyIdCol} = ?;`;
        params = [uploadId, q];
      } else {
        // 公司名稱模糊 + 限縮在這次上傳
        sql = `SELECT * FROM ${tableName} WHERE upload_id = ? AND ${companyNameCol} LIKE ?;`;
        params = [uploadId, `%${q}%`];
      }

      const rowsRes = await db.prepare(sql).bind(...params).all();
      const rows = rowsRes.results || [];

      for (const row of rows) {
        items.push({
          service_id: serviceId,
          service_name: serviceName,
          table_name: tableName,
          upload_id: uploadId,
          original_filename: upload.original_filename || null,
          uploaded_at: upload.uploaded_at || null,
          uploaded_by_email: upload.uploaded_by_email || null,
          row,
        });
      }
    }
  }

  return { isCompanyId, items };
}


    const rowsRes = await db.prepare(sql).bind(...params).all();
    const rows = rowsRes.results || [];

    for (const row of rows) {
      items.push({
        service_id: serviceId,
        service_name: serviceName,
        table_name: tableName,
        uploaded_at: upload.uploaded_at || null,
        uploaded_by_email: upload.uploaded_by_email || null,
        row,
      });
    }
  }

  return { isCompanyId, items };
}


async function handleSearch(env, email, url) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const q = (url.searchParams.get("q") || "").trim();
  if (!q) return json({ error: "q is required" }, 400);

  const { isCompanyId, items } = await searchAll(env, q);

  return json({
    query: q,
    is_company_id: isCompanyId,
    count: items.length,
    results: items,
  });
}

async function handleSearchExport(env, email, url) {
  if (!email) {
    return new Response("Unauthorized", { status: 401 });
  }

  const q = (url.searchParams.get("q") || "").trim();
  if (!q) {
    return new Response("q is required", { status: 400 });
  }

  const { items } = await searchAll(env, q);

  const fixedCols = [
    "service_id",
    "service_name",
    "table_name",
    "uploaded_at",
    "uploaded_by_email",
  ];
  const dynamicCols = new Set();

  for (const item of items) {
    Object.keys(item.row).forEach((k) => dynamicCols.add(k));
  }

  const allCols = fixedCols.concat(Array.from(dynamicCols));

  const esc = (val) => {
    if (val === null || val === undefined) return "";
    const s = String(val);
    if (/[",\n]/.test(s)) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  const lines = [];
  lines.push(allCols.map(esc).join(","));

  for (const item of items) {
    const row = item.row;
    const rowValues = [];

    for (const col of allCols) {
      if (col === "service_id") rowValues.push(esc(item.service_id));
      else if (col === "service_name") rowValues.push(esc(item.service_name));
      else if (col === "table_name") rowValues.push(esc(item.table_name));
      else if (col === "uploaded_at") rowValues.push(esc(item.uploaded_at));
      else if (col === "uploaded_by_email")
        rowValues.push(esc(item.uploaded_by_email));
      else rowValues.push(esc(row[col]));
    }

    lines.push(rowValues.join(","));
  }

  const csv = lines.join("\r\n");
  const filenameSafe =
    q.replace(/[^a-zA-Z0-9_\u4e00-\u9fff]/g, "_") || "search";

  return new Response(csv, {
    status: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filenameSafe}.csv"`,
    },
  });
}

// ========== 後台管理 API ==========

async function handleListServiceUploads(env, email, serviceId, url) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const db = env.DB;

  const service = await db
    .prepare("SELECT * FROM service_items WHERE id = ?")
    .bind(serviceId)
    .first();

  if (!service) return json({ error: "Service not found" }, 404);
  if (service.owner_email !== email) {
    return json({ error: "Forbidden: only owner can view uploads" }, 403);
  }

  const includeDeleted = url.searchParams.get("include_deleted") === "1";

  let sql = `
    SELECT id, service_id, original_filename, header_row_index,
           uploaded_by_email, uploaded_at, row_count,
           company_id_header, company_name_header,
           status, deleted_at
    FROM uploads
    WHERE service_id = ?
  `;
  const params = [serviceId];

  if (!includeDeleted) {
    sql += " AND status <> 'deleted'";
  }

  sql += " ORDER BY uploaded_at DESC, id DESC;";

  const res = await db.prepare(sql).bind(...params).all();
  return json(res.results || []);
}

async function handleDeleteUpload(env, email, uploadId) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const db = env.DB;

  const row = await db
    .prepare(
      `
      SELECT u.*, s.owner_email
      FROM uploads u
      JOIN service_items s ON u.service_id = s.id
      WHERE u.id = ?;
    `
    )
    .bind(uploadId)
    .first();

  if (!row) return json({ error: "Upload not found" }, 404);
  if (row.owner_email !== email) {
    return json({ error: "Forbidden: only owner can delete upload" }, 403);
  }

  await db
    .prepare(
      `
      UPDATE uploads
      SET status = 'deleted',
          deleted_at = CURRENT_TIMESTAMP
      WHERE id = ?;
    `
    )
    .bind(uploadId)
    .run();

  const updated = await db
    .prepare(
      `
      SELECT id, service_id, original_filename, header_row_index,
             uploaded_by_email, uploaded_at, row_count,
             company_id_header, company_name_header,
             status, deleted_at
      FROM uploads
      WHERE id = ?;
    `
    )
    .bind(uploadId)
    .first();

  return json(updated);
}

async function handleTransferServiceOwner(request, env, email, serviceId) {
  if (!email) return json({ error: "Unauthorized" }, 401);

  const db = env.DB;

  const service = await db
    .prepare("SELECT * FROM service_items WHERE id = ?")
    .bind(serviceId)
    .first();

  if (!service) return json({ error: "Service not found" }, 404);
  if (service.owner_email !== email) {
    return json({ error: "Forbidden: only current owner can transfer" }, 403);
  }

  const body = await request.json();
  const newEmail = body.new_owner_email
    ? body.new_owner_email.trim()
    : "";
  const newDisplayName =
    (body.new_owner_display_name || "").trim() ||
    (newEmail.split("@")[0] || "");

  if (!newEmail) {
    return json({ error: "new_owner_email is required" }, 400);
  }

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        display_name TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );
    `)
    .run();

  const existingUser = await db
    .prepare("SELECT email FROM users WHERE email = ?")
    .bind(newEmail)
    .first();

  if (!existingUser) {
    await db
      .prepare("INSERT INTO users (email, display_name) VALUES (?, ?)")
      .bind(newEmail, newDisplayName)
      .run();
  }

  await db
    .prepare(
      `
      UPDATE service_items
      SET owner_email = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?;
    `
    )
    .bind(newEmail, serviceId)
    .run();

  const updatedService = await db
    .prepare("SELECT * FROM service_items WHERE id = ?")
    .bind(serviceId)
    .first();

  return json(updatedService);
}
