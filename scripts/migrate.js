import Database from "better-sqlite3";
import fs from "node:fs";

const db = new Database("data/app.sqlite");
db.pragma("journal_mode = WAL");
const sql = fs.readFileSync("sql/00_init.sql", "utf8");
db.exec(sql);
console.log("✅ migrated");
