import { createServer } from "node:http";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = normalize(join(__filename, ".."));
const ROOT_DIR = normalize(join(__dirname, ".."));
const APP_DIR = join(ROOT_DIR, "HabitPlannerApp");
const DATA_DIR = join(APP_DIR, "server_data");
const DB_PATH = join(DATA_DIR, "sudoku.db");
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const ALLOWED_ORIGIN = process.env.SUDOKU_ALLOWED_ORIGIN || "http://localhost:3000";

mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY,
        theme TEXT NOT NULL DEFAULT 'sunrise',
        game_state_json TEXT,
        game_state_updated_at INTEGER NOT NULL DEFAULT 0,
        records_json TEXT NOT NULL DEFAULT '{}'
    );
`);

const statements = {
    findUserByUsername: db.prepare("SELECT * FROM users WHERE username = ?"),
    findUserById: db.prepare("SELECT * FROM users WHERE id = ?"),
    insertUser: db.prepare(
        "INSERT INTO users (username, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?)"
    ),
    insertSession: db.prepare(
        "INSERT INTO sessions (token, user_id, created_at, last_seen_at) VALUES (?, ?, ?, ?)"
    ),
    findSession: db.prepare("SELECT * FROM sessions WHERE token = ?"),
    touchSession: db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token = ?"),
    deleteSession: db.prepare("DELETE FROM sessions WHERE token = ?"),
    ensureProfile: db.prepare(
        "INSERT INTO profiles (user_id, theme, game_state_json, game_state_updated_at, records_json) VALUES (?, 'sunrise', NULL, 0, '{}') ON CONFLICT(user_id) DO NOTHING"
    ),
    getProfile: db.prepare("SELECT * FROM profiles WHERE user_id = ?"),
    updateTheme: db.prepare("UPDATE profiles SET theme = ? WHERE user_id = ?"),
    updateState: db.prepare(
        "UPDATE profiles SET game_state_json = ?, game_state_updated_at = ?, theme = ? WHERE user_id = ?"
    ),
    updateRecords: db.prepare("UPDATE profiles SET records_json = ? WHERE user_id = ?")
};

function nowIso() {
    return new Date().toISOString();
}

function sendJson(response, statusCode, payload) {
    response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
    response.end(JSON.stringify(payload));
}

function setCorsHeaders(response) {
    response.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
}

function readBody(request) {
    return new Promise((resolve, reject) => {
        let raw = "";
        request.on("data", (chunk) => {
            raw += chunk;
            if (raw.length > 1_000_000) {
                reject(new Error("Слишком большой запрос."));
                request.destroy();
            }
        });
        request.on("end", () => {
            if (!raw) {
                resolve({});
                return;
            }
            try {
                resolve(JSON.parse(raw));
            } catch {
                reject(new Error("Некорректный JSON."));
            }
        });
        request.on("error", reject);
    });
}

function passwordHash(password, salt) {
    return scryptSync(password, salt, 64).toString("hex");
}

function createPasswordRecord(password) {
    const salt = randomBytes(16).toString("hex");
    return { salt, hash: passwordHash(password, salt) };
}

function verifyPassword(password, salt, hash) {
    const actual = Buffer.from(passwordHash(password, salt), "hex");
    const expected = Buffer.from(hash, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function parseToken(request) {
    const authHeader = request.headers.authorization || "";
    return authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
}

function getUserFromRequest(request) {
    const token = parseToken(request);
    if (!token) {
        return null;
    }

    const session = statements.findSession.get(token);
    if (!session) {
        return null;
    }

    statements.touchSession.run(nowIso(), token);
    const user = statements.findUserById.get(session.user_id);
    if (!user) {
        statements.deleteSession.run(token);
        return null;
    }

    statements.ensureProfile.run(user.id);
    const profile = statements.getProfile.get(user.id);
    return { token, user, profile };
}

function createSession(userId) {
    const token = randomBytes(32).toString("hex");
    const createdAt = nowIso();
    statements.insertSession.run(token, userId, createdAt, createdAt);
    return token;
}

function sanitizeStaticPath(urlPath) {
    const relative = urlPath === "/" ? "sudoku.html" : urlPath.replace(/^\/+/, "");
    const filePath = normalize(join(APP_DIR, relative));
    return filePath.startsWith(APP_DIR) ? filePath : null;
}

function sendStaticFile(response, filePath) {
    if (!filePath || !existsSync(filePath)) {
        sendJson(response, 404, { message: "Файл не найден." });
        return;
    }

    const contentType = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8"
    }[extname(filePath)] || "application/octet-stream";

    response.writeHead(200, { "Content-Type": contentType });
    response.end(readFileSync(filePath));
}

function normalizeRecords(value) {
    const raw = value && typeof value === "object" ? value : {};
    return {
        easy: Array.isArray(raw.easy) ? raw.easy : [],
        medium: Array.isArray(raw.medium) ? raw.medium : [],
        hard: Array.isArray(raw.hard) ? raw.hard : [],
        expert: Array.isArray(raw.expert) ? raw.expert : []
    };
}

async function handleApi(request, response, pathname) {
    if (request.method === "POST" && pathname === "/api/register") {
        const body = await readBody(request);
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (username.length < 3) {
            sendJson(response, 400, { message: "Имя пользователя должно быть не короче 3 символов." });
            return;
        }
        if (password.length < 6) {
            sendJson(response, 400, { message: "Пароль должен быть не короче 6 символов." });
            return;
        }
        if (statements.findUserByUsername.get(username)) {
            sendJson(response, 409, { message: "Такое имя пользователя уже занято." });
            return;
        }

        const { salt, hash } = createPasswordRecord(password);
        const createdAt = nowIso();
        const result = statements.insertUser.run(username, salt, hash, createdAt);
        const userId = Number(result.lastInsertRowid);
        statements.ensureProfile.run(userId);
        const token = createSession(userId);
        sendJson(response, 200, { token, username });
        return;
    }

    if (request.method === "POST" && pathname === "/api/login") {
        const body = await readBody(request);
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        const user = statements.findUserByUsername.get(username);

        if (!user || !verifyPassword(password, user.password_salt, user.password_hash)) {
            sendJson(response, 401, { message: "Неверное имя пользователя или пароль." });
            return;
        }

        statements.ensureProfile.run(user.id);
        const token = createSession(user.id);
        sendJson(response, 200, { token, username: user.username });
        return;
    }

    const sessionData = getUserFromRequest(request);
    if (!sessionData) {
        sendJson(response, 401, { message: "Требуется авторизация." });
        return;
    }

    const { token, user, profile } = sessionData;

    if (request.method === "POST" && pathname === "/api/logout") {
        statements.deleteSession.run(token);
        sendJson(response, 200, { ok: true });
        return;
    }

    if (request.method === "GET" && pathname === "/api/me") {
        sendJson(response, 200, { username: user.username, theme: profile.theme });
        return;
    }

    if (request.method === "GET" && pathname === "/api/state") {
        sendJson(response, 200, {
            state: profile.game_state_json ? JSON.parse(profile.game_state_json) : null,
            updatedAt: profile.game_state_updated_at || 0
        });
        return;
    }

    if (request.method === "POST" && pathname === "/api/state") {
        const body = await readBody(request);
        const state = body.state;
        const updatedAt = Number(state?.updatedAt || Date.now());
        const theme = typeof state?.currentTheme === "string" ? state.currentTheme : profile.theme || "sunrise";
        statements.updateState.run(JSON.stringify(state || {}), updatedAt, theme, user.id);
        sendJson(response, 200, { ok: true, updatedAt });
        return;
    }

    if (request.method === "GET" && pathname === "/api/records") {
        sendJson(response, 200, { records: normalizeRecords(JSON.parse(profile.records_json || "{}")) });
        return;
    }

    if (request.method === "POST" && pathname === "/api/records") {
        const body = await readBody(request);
        const difficulty = String(body.difficulty || "");
        const record = body.record && typeof body.record === "object" ? body.record : null;
        const records = normalizeRecords(JSON.parse(profile.records_json || "{}"));

        if (!records[difficulty] || !record) {
            sendJson(response, 400, { message: "Некорректные данные рекорда." });
            return;
        }

        records[difficulty].push(record);
        records[difficulty].sort((first, second) => first.time - second.time);
        records[difficulty] = records[difficulty].slice(0, 5);
        statements.updateRecords.run(JSON.stringify(records), user.id);
        sendJson(response, 200, { records });
        return;
    }

    sendJson(response, 404, { message: "Маршрут не найден." });
}

const server = createServer(async (request, response) => {
    setCorsHeaders(response);

    if (request.method === "OPTIONS") {
        response.writeHead(204);
        response.end();
        return;
    }

    try {
        const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
        if (url.pathname.startsWith("/api/")) {
            await handleApi(request, response, url.pathname);
            return;
        }

        sendStaticFile(response, sanitizeStaticPath(url.pathname));
    } catch (error) {
        sendJson(response, 500, { message: error instanceof Error ? error.message : "Внутренняя ошибка сервера." });
    }
});

server.listen(PORT, HOST, () => {
    console.log(`Sudoku server running on http://localhost:${PORT}`);
    console.log(`Database: ${DB_PATH}`);
});
