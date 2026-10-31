import { defineMiddleware } from "astro:middleware";

/**
 * Security headers for the public site.
 *
 * EmDash already sends nosniff, Referrer-Policy and Permissions-Policy on every
 * response and its own strict CSP on /_emdash (admin + API). This adds a
 * Content-Security-Policy and HTTPS hardening to the public pages it leaves open.
 *
 * Only these outside origins are allowed:
 * - fonts.googleapis.com / fonts.gstatic.com: the Dosis web font
 * - static.cloudflareinsights.com / cloudflareinsights.com: Cloudflare Web Analytics
 *
 * 'unsafe-inline' for scripts is required by the EmDash editor toolbar and Astro's
 * small inline scripts; the page takes no visitor input, and no third-party script
 * hosts are allowed, so injected markup has nowhere to load code from.
 */
const CSP = [
	"default-src 'self'",
	"script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com",
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
	"font-src 'self' https://fonts.gstatic.com",
	"img-src 'self' data: blob:",
	"media-src 'self'",
	"connect-src 'self' https://cloudflareinsights.com",
	"frame-src 'none'",
	"frame-ancestors 'none'",
	"object-src 'none'",
	"base-uri 'self'",
	"form-action 'self'",
	"upgrade-insecure-requests",
].join("; ");

export const onRequest = defineMiddleware(async (context, next) => {
	// Copy so headers are writable even when the upstream response's are immutable.
	const response = await next();
	const isPublic = !context.url.pathname.startsWith("/_emdash");

	// Headers are set in place (not on a copy) so Astro's pending cookies, such as the
	// admin sign-in session, are kept. Responses with locked headers are left as they are.
	try {
		// Every response: force HTTPS for a year and isolate the browsing context.
		response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
		response.headers.set("Cross-Origin-Opener-Policy", "same-origin");

		// Public pages only; EmDash manages headers for its admin, API and media routes.
		if (isPublic) {
			response.headers.set("Content-Security-Policy", CSP);
			response.headers.set("X-Frame-Options", "DENY");
		}
	} catch {
		// Immutable headers (e.g. a passthrough fetch response); nothing to add.
	}

	return response;
});
