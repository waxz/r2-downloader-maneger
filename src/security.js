// In-memory data structures (Isolated per active Worker isolate)
const bans = new Map();       
const rates = new Map();      
const authFails = new Map();  

// Default configuration fallback values
const DEFAULT_CONFIG = {
  rateLimit: 100,         // Max requests per minute
  maxAuthFails: 5,       // Max failed auths before ban
  banDuration: 3600000,   // Ban duration in milliseconds (1 hour)
};

/**
 * 1. Checks if an IP is banned and tracks/limits request rates.
 * 
 * @param {Request} request 
 * @param {object} [customConfig] - Optional runtime overrides for thresholds
 * @returns {Response|null} - Returns a Response if blocked/rate-limited, or null to proceed
 */
export function checkRateAndBan(request, customConfig = {}) {
  const config = { ...DEFAULT_CONFIG, ...customConfig };
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const now = Date.now();
  const currentMinute = Math.floor(now / 60000);

  // Check Ban Status
  if (bans.has(ip)) {
    if (now < bans.get(ip)) {
      return new Response("Access Denied: Temporarily banned.", { status: 403 });
    }
    bans.delete(ip); // Ban expired, clear it
  }

  // Check & Update Rate Limit
  let rateData = rates.get(ip) || { count: 0, windowMinute: currentMinute };
  if (rateData.windowMinute !== currentMinute) {
    rateData = { count: 0, windowMinute: currentMinute };
  }
  
  if (rateData.count >= config.rateLimit) {
    return new Response("Too Many Requests.", { status: 429 });
  }
  
  rateData.count++;
  rates.set(ip, rateData);

  return null; // Clean traffic, proceed
}

/**
 * 2. Records an auth result and issues a ban if failures cross the threshold.
 * 
 * @param {Request} request 
 * @param {boolean} isSuccess - True if login succeeded, false if it failed
 * @param {object} [customConfig] - Optional runtime overrides for thresholds
 * @returns {boolean} - Returns true if the IP was just banned, false otherwise
 */
export function recordAuthResult(request, isSuccess, customConfig = {}) {
  const config = { ...DEFAULT_CONFIG, ...customConfig };
  const ip = request.headers.get("cf-connecting-ip") || "unknown";

  if (isSuccess) {
    authFails.delete(ip); // Success: Clear history
    return false;
  }

  // Failure: Track and evaluate thresholds
  let failData = authFails.get(ip) || { count: 0 };
  failData.count++;
  
  if (failData.count >= config.maxAuthFails) {
    bans.set(ip, Date.now() + config.banDuration); 
    authFails.delete(ip); 
    return true; // IP is now banned
  }

  authFails.set(ip, failData);
  return false;
}
