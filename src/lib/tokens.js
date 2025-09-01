import jwt from "jsonwebtoken";
import argon2 from "argon2";
import { customAlphabet } from "nanoid";
const nanoid = customAlphabet("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 40);

export function signJWT(payload, ttlMinutes = 45) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlMinutes * 60;
  const token = jwt.sign({ ...payload, iat: now, exp }, process.env.JWT_SECRET);
  return { token, exp };
}

export async function newRefresh() {
  const raw = nanoid();
  const hash = await argon2.hash(raw);
  return { raw, hash };
}

export async function verifyRefresh(raw, hash) {
  try { return await argon2.verify(hash, raw); }
  catch { return false; }
}
