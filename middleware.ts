import { next } from "@vercel/edge";

export const config = {
  matcher: "/:path*",
};

export default async function middleware(request: Request) {
  const authHeader = request.headers.get("authorization");
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return new Response("Unauthorized: Missing token", { status: 401 });
  }
  
  const token = authHeader.substring(7);
  
  try {
    // GitHub Actions OIDCトークンを検証
    const jwksUrl = "https://token.actions.githubusercontent.com/.well-known/jwks";
    const response = await fetch(jwksUrl);
    const jwks = await response.json();
    
    // トークンをデコード（簡易版 - 本番はjoseライブラリ推奨）
    const [headerB64, payloadB64, signatureB64] = token.split(".");
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    
    // 発行者を検証
    if (payload.iss !== "https://token.actions.githubusercontent.com") {
      return new Response("Invalid issuer", { status: 403 });
    }
    
    // audienceを検証
    const expectedAudience = process.env.EXPECTED_AUDIENCE || "https://github.com/YOUR_USERNAME";
    if (payload.aud !== expectedAudience) {
      return new Response("Invalid audience", { status: 403 });
    }
    
    // リポジトリを検証（optional）
    const allowedRepo = process.env.ALLOWED_REPO;
    if (allowedRepo && payload.repository !== allowedRepo) {
      return new Response(`Forbidden: Invalid repository ${payload.repository}`, { status: 403 });
    }
    
    // 有効期限チェック
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return new Response("Token expired", { status: 401 });
    }
    
    return next();
  } catch (error) {
    return new Response(`Token verification failed: ${error.message}`, { status: 401 });
  }
}
