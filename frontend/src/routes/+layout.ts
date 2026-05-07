// Pure SPA: no prerender, no SSR. The canonical UI now ships via
// adapter-node so server runtime exists, but every page mounts data
// from /api at runtime — there's nothing meaningful to prerender, and
// dynamic routes like /investigations/[id] would error during the
// crawl. Rendering happens entirely client-side.
export const prerender = false;
export const ssr = false;
