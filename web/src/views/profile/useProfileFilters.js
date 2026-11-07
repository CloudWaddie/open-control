import { useCallback, useEffect, useState } from 'react';
import { api } from '../../api.js';

// A profile's enabled filters, services and lists, keyed "kind:ref". `update`
// applies the change on screen at once and rolls back if the server refuses.
export function useProfileFilters(profileId) {
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState('');
  const [pending, setPending] = useState({});

  useEffect(() => {
    api('GET', `/profiles/${profileId}/filters`)
      .then((list) => setEntries(Object.fromEntries(list.map((e) => [`${e.kind}:${e.ref}`, e]))))
      .catch((e) => setError(e.message));
  }, [profileId]);

  const update = useCallback(
    async (kind, ref, change) => {
      const key = `${kind}:${ref}`;
      const body = { kind, ref, ...change };
      let previous;
      setError('');
      setEntries((cur) => {
        previous = cur[key];
        const next = { ...cur };
        if (change.state === 'off') delete next[key];
        else next[key] = body;
        return next;
      });
      setPending((p) => ({ ...p, [key]: true }));
      try {
        await api('PUT', `/profiles/${profileId}/filters`, body);
      } catch (e) {
        setError(e.message);
        setEntries((cur) => {
          const next = { ...cur };
          if (previous) next[key] = previous;
          else delete next[key];
          return next;
        });
      } finally {
        setPending((p) => {
          const next = { ...p };
          delete next[key];
          return next;
        });
      }
    },
    [profileId],
  );

  return { entries, error, setError, pending, update };
}
