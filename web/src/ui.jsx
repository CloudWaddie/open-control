import { useState } from 'react';
import { AlertCircleIcon, CheckIcon, CopyIcon, XIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';

export function PageHeader({ title, description, children }) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && (
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {children && <div className="flex shrink-0 items-center gap-2">{children}</div>}
    </div>
  );
}

export function ErrorLine({ error, onDismiss }) {
  if (!error) return null;
  return (
    <Alert variant="destructive">
      <AlertCircleIcon />
      <AlertTitle>Request failed</AlertTitle>
      <AlertDescription>{error}</AlertDescription>
      {onDismiss && (
        <Button
          variant="ghost"
          size="icon-xs"
          className="absolute top-2 right-2"
          aria-label="Dismiss"
          onClick={onDismiss}
        >
          <XIcon />
        </Button>
      )}
    </Alert>
  );
}

// Destructive actions ask once in a dialog. `onConfirm` may be async; the
// dialog closes when it settles.
export function Confirm({ label, title, description, action, onConfirm, variant = 'ghost', icon }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
      setOpen(false);
    }
  }

  return (
    <>
      <Button
        variant={variant}
        size="sm"
        className={variant === 'ghost' ? 'text-destructive hover:bg-destructive/10 hover:text-destructive' : ''}
        onClick={() => setOpen(true)}
      >
        {icon}
        {label}
      </Button>
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            {description && <AlertDialogDescription>{description}</AlertDialogDescription>}
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <Button variant="destructive" disabled={busy} onClick={run}>
              {action || label}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

// options: [{ value, label }]. Values are strings; callers convert ids.
export function SimpleSelect({ value, onChange, options, className, id, disabled, placeholder }) {
  return (
    <Select
      items={options}
      value={value}
      onValueChange={(v) => v != null && onChange(v)}
      disabled={disabled}
    >
      <SelectTrigger id={id} className={cn('w-full', className)}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

const TONES = {
  block: 'bg-block-soft text-block',
  allow: 'bg-ok-soft text-ok',
  rewrite: 'bg-rewrite-soft text-rewrite',
  redirect: 'bg-redirect-soft text-redirect',
  forward: 'bg-muted text-muted-foreground',
  refused: 'bg-warn-soft text-warn',
  error: 'bg-warn-soft text-warn',
  healthy: 'bg-ok-soft text-ok',
  down: 'bg-block-soft text-block',
  unknown: 'bg-muted text-muted-foreground',
};

const DOTS = {
  healthy: 'bg-ok',
  down: 'bg-block',
  unknown: 'bg-muted-foreground/60',
};

export function Tag({ tone, children, dot }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 items-center gap-1.5 rounded-full px-2 text-xs font-medium whitespace-nowrap',
        TONES[tone] || 'bg-muted text-muted-foreground',
      )}
    >
      {dot && <span className={cn('size-1.5 rounded-full', DOTS[tone] || 'bg-current')} />}
      {children}
    </span>
  );
}

// Domains, IPs and CIDRs.
export function Mono({ className, ...props }) {
  return <span className={cn('font-mono text-[0.8125rem] break-all', className)} {...props} />;
}

export function TableSkeleton({ rows = 4 }) {
  return (
    <div className="flex flex-col gap-3 py-2">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-5" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children }) {
  return (
    <Empty className="py-10">
      <EmptyHeader>
        {Icon && (
          <EmptyMedia variant="icon">
            <Icon />
          </EmptyMedia>
        )}
        <EmptyTitle>{title}</EmptyTitle>
        {children && <EmptyDescription>{children}</EmptyDescription>}
      </EmptyHeader>
    </Empty>
  );
}

// A secret the server returns once. Copy needs a secure context; over plain
// HTTP the text stays selectable.
export function SecretValue({ value }) {
  const [copied, setCopied] = useState(false);
  const canCopy = typeof navigator !== 'undefined' && !!navigator.clipboard && window.isSecureContext;

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="flex items-center gap-2 rounded-lg border bg-background p-1 pl-3">
      <code className="min-w-0 flex-1 font-mono text-sm break-all select-all">{value}</code>
      {canCopy && (
        <Button variant="outline" size="sm" onClick={copy}>
          {copied ? <CheckIcon /> : <CopyIcon />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      )}
    </div>
  );
}
