// GET /api/auth/discord — redirect to the Discord OAuth2 authorization page.
// A random state is stored in a short-lived cookie for CSRF protection on callback.

import crypto from "crypto";
import { cfg, isDiscordOAuthReady } from "@/lib/config";
import { appOrigin } from "@/lib/origin";

function redirectUri(req: Request): string {
  return `${appOrigin(req)}/api/auth/discord/callback`;
}

export async function GET(req: Request) {
  if (!isDiscordOAuthReady()) {
    const headers = new Headers();
    headers.set("Location", "/?error=oauth_belum_disiapkan");
    return new Response(null, { status: 302, headers });
  }
  const state = crypto.randomBytes(16).toString("hex");
  const uri = redirectUri(req);
  console.log(`[oauth] redirect_uri=${uri}`);
  const params = new URLSearchParams({
    client_id: cfg.discordClientId,
    redirect_uri: uri,
    response_type: "code",
    scope: "identify guilds",
    state,
  });

  const headers = new Headers();
  headers.set("Location", `https://discord.com/oauth2/authorize?${params.toString()}`);
  headers.append(
    "set-cookie",
    `thor_oauth_state=${state}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=600`
  );

  return new Response(null, { status: 302, headers });
}
