import { useState } from 'react';

export function ErrorLine({ error }) {
  if (!error) return null;
  return <p className="error">{error}</p>;
}

// Two-step button for destructive actions: first click arms, second confirms.
export function Confirm({ label, onConfirm }) {
  const [armed, setArmed] = useState(false);
  if (!armed) {
    return (
      <button className="link danger" onClick={() => setArmed(true)}>
        {label}
      </button>
    );
  }
  return (
    <span>
      <button className="link danger" onClick={onConfirm}>
        confirm
      </button>{' '}
      <button className="link" onClick={() => setArmed(false)}>
        cancel
      </button>
    </span>
  );
}
