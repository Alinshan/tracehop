import axios from "axios";
import { TraceResult } from "./types";

export async function traceRedirects(url: string, maxRedirects = 10): Promise<TraceResult[]> {
  const results: TraceResult[] = [];
  let currentUrl = url;
  
  for (let i = 0; i < maxRedirects; i++) {
    try {
      const response = await axios.get(currentUrl, {
        maxRedirects: 0,
        validateStatus: status => status >= 200 && status < 400
      });

      const redirected = !!response.headers.location;
      results.push({
        url: currentUrl,
        status: response.status,
        redirected,
        finalUrl: redirected ? response.headers.location : undefined
      });

      if (!redirected) break;
      currentUrl = response.headers.location;
    } catch (error: any) {
      break;
    }
  }

  return results;
}
