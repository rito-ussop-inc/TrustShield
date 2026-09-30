import { useEffect, useState } from 'react';

export function useProviderStatus() {
  const [status, setStatus] = useState<Record<string, string>>({});
  useEffect(() => {
    fetch('/api/v1/providers/status').then((r) => r.json()).then(setStatus).catch(() => {});
  }, []);
  return status;
}
