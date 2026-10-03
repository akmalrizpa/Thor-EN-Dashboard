// GET /api/auth/discord/callback — exchange the code for a token, fetch the
// profile, upsert the user, then set the session cookie and return home.

import crypto from "crypto";
import { db } from "@/lib/db";
import { cfg, isDiscordOAuthReady } from "@/lib/config";
import { appOrigin } from "@/lib/origin";
import { createSessionToken, sessionCookie } from "@/lib/session";

const DISCORD_FETCH_TIMEOUT_MS = 8000;

async function discordFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DISCORD_FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal, cache: "no-store" });
  } finally {
    clearTimeout(timer);
  }
}

function redirectUri(req: Request): string {
  return `${appOrigin(req)}/api/auth/discord/callback`;
}

function fail(req: Request, reason: string): Response {
  const headers = new Headers();
  headers.set("Location", `/?error=${reason}`);
  headers.append("set-cookie", "thor_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  return new Response(null, { status: 302, headers });
}

function readStateCookie(req: Request): string | null {
  const raw = req.headers.get("cookie") ?? "";
  const match = raw
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith("thor_oauth_state="));
  return match ? match.slice("thor_oauth_state=".length) : null;
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!isDiscordOAuthReady()) {
    return fail(req, "oauth_belum_disiapkan");
  }
  if (!code) {
    return fail(req, "login_dibatalkan");
  }

  const expected = readStateCookie(req);
  if (!state || !expected || !timingSafeEqualHex(state, expected)) {
    return fail(req, "sesi_kedaluwarsa");
  }

  try {
    const tokenRes = await discordFetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: cfg.discordClientId,
        client_secret: cfg.discordClientSecret,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri(req),
      }),
    });
    if (!tokenRes.ok) {
      return fail(req, "login_gagal");
    }
    const token = (await tokenRes.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };
    if (!token.access_token) {
      return fail(req, "login_gagal");
    }

    const meRes = await discordFetch("https://discord.com/api/users/@me", {
      headers: { authorization: `Bearer ${token.access_token}` },
    });
    if (!meRes.ok) {
      return fail(req, "profil_tidak_terbaca");
    }
    const profile = (await meRes.json()) as {
      id: string;
      username: string;
      global_name?: string;
      avatar?: string;
    };

    const isAdmin = cfg.adminDiscordIds.includes(profile.id);
    const tokenExpiresAt = new Date(Date.now() + (token.expires_in ?? 604800) * 1000);
    const user = await db.user.upsert({
      where: { discordId: profile.id },
      create: {
        discordId: profile.id,
        username: profile.username,
        globalName: profile.global_name ?? null,
        avatar: profile.avatar ?? null,
        isAdmin,
        accessToken: token.access_token,
        refreshToken: token.refresh_token ?? null,
        tokenExpiresAt,
      },
      update: {
        username: profile.username,
        globalName: profile.global_name ?? null,
        avatar: profile.avatar ?? null,
        isAdmin,
        accessToken: token.access_token,
        refreshToken: token.refresh_token ?? null,
        tokenExpiresAt,
      },
    });

    let sessionToken: string;
    try {
      sessionToken = createSessionToken(user);
    } catch (err) {
      console.error("[oauth] refusing to create a session token:", (err as Error).message);
      return fail(req, "konfigurasi_tidak_aman");
    }
    const cookie = sessionCookie(sessionToken);

    const headers = new Headers();
    headers.set("Location", "/");
    headers.append(
      "set-cookie",
      `${cookie.name}=${cookie.value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${cookie.maxAge}${
        cookie.secure ? "; Secure" : ""
      }`
    );
    headers.append("set-cookie", "thor_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");

    return new Response(null, { status: 302, headers });
  } catch (err) {
    console.error("[oauth] callback failed:", err instanceof Error ? err.message : err);
    return fail(req, "login_gagal");
  }
}

function timingSafeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
