// src/lib/octo.js
import fs from "node:fs";
import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";

function getPrivateKey() {
  if (process.env.GITHUB_APP_PRIVATE_KEY) return process.env.GITHUB_APP_PRIVATE_KEY;
  if (process.env.GITHUB_APP_PRIVATE_KEY_PATH) {
    return fs.readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, "utf8");
  }
  throw new Error("Missing GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH");
}

export function appOcto() {
  const privateKey = getPrivateKey();
  return new Octokit({
    authStrategy: createAppAuth,
    auth: { appId: process.env.GITHUB_APP_ID, privateKey }
  });
}

export function instOcto(installationId) {
  const privateKey = getPrivateKey();
  return new Octokit({
    authStrategy: createAppAuth,
    auth: { appId: process.env.GITHUB_APP_ID, privateKey, installationId }
  });
}
