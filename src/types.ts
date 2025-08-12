export interface TraceResult {
  url: string;
  status: number;
  redirected: boolean;
  finalUrl?: string;
}
