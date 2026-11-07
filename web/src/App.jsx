import { useEffect, useState } from 'react';
import {
  ActivityIcon,
  ChevronsUpDownIcon,
  GaugeIcon,
  KeyRoundIcon,
  ListXIcon,
  LogOutIcon,
  MonitorIcon,
  MoonIcon,
  NetworkIcon,
  ScrollTextIcon,
  ShieldIcon,
  SunIcon,
  WaypointsIcon,
} from 'lucide-react';
import { api, can, getToken, setToken } from './api.js';
import { useTheme } from './theme.js';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from '@/components/ui/sidebar';
import { Skeleton } from '@/components/ui/skeleton';
import { TooltipProvider } from '@/components/ui/tooltip';
import Overview from './views/Overview.jsx';
import Exits from './views/Exits.jsx';
import Logs from './views/Logs.jsx';
import Profiles from './views/Profiles.jsx';
import Endpoints from './views/Endpoints.jsx';
import Blocklists from './views/Blocklists.jsx';
import Tokens from './views/Tokens.jsx';
import Audit from './views/Audit.jsx';

// Each nav entry names the minimum role it needs. Viewers see read-only
// versions of the filtering pages; tokens and audit are admin-only.
const NAV = [
  {
    label: 'Monitor',
    items: [
      { id: 'overview', label: 'Overview', icon: GaugeIcon, min: 'viewer', view: Overview },
      { id: 'logs', label: 'Query log', icon: ActivityIcon, min: 'viewer', view: Logs },
    ],
  },
  {
    label: 'Filtering',
    items: [
      { id: 'profiles', label: 'Profiles', icon: ShieldIcon, min: 'viewer', view: Profiles },
      { id: 'endpoints', label: 'Endpoints', icon: NetworkIcon, min: 'viewer', view: Endpoints },
      { id: 'blocklists', label: 'Blocklists', icon: ListXIcon, min: 'viewer', view: Blocklists },
      { id: 'exits', label: 'Exit nodes', icon: WaypointsIcon, min: 'viewer', view: Exits },
    ],
  },
  {
    label: 'Admin',
    items: [
      { id: 'tokens', label: 'API tokens', icon: KeyRoundIcon, min: 'admin', view: Tokens },
      { id: 'audit', label: 'Audit log', icon: ScrollTextIcon, min: 'admin', view: Audit },
    ],
  },
];

// "#/profiles/3/services" → ['profiles', '3', 'services']
function currentRoute() {
  const path = window.location.hash.replace(/^#\/?/, '') || 'overview';
  return path.split('/').filter(Boolean);
}

export function BrandMark({ className = 'size-7' }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden="true">
      <rect width="24" height="24" rx="6" className="fill-primary" />
      <path
        d="M6 8h12M8.5 12h7M11 16h2"
        className="stroke-primary-foreground"
        strokeWidth="2.2"
        strokeLinecap="round"
      />
    </svg>
  );
}

export default function App() {
  const [me, setMe] = useState(null); // { name, role } once signed in
  const [checking, setChecking] = useState(!!getToken());
  const [route, setRoute] = useState(currentRoute());
  const [theme, setTheme] = useTheme();

  useEffect(() => {
    const onHash = () => setRoute(currentRoute());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  // Restore the session from a token already in this tab.
  useEffect(() => {
    if (!getToken()) return;
    api('GET', '/whoami')
      .then(setMe)
      .catch(() => setToken(''))
      .finally(() => setChecking(false));
  }, []);

  if (checking) {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Skeleton className="size-8 rounded-lg" />
      </div>
    );
  }
  if (!me) return <Login onSignedIn={setMe} />;

  const groups = NAV.map((g) => ({ ...g, items: g.items.filter((n) => can(me.role, n.min)) })).filter(
    (g) => g.items.length,
  );
  const visible = groups.flatMap((g) => g.items);
  const active = visible.find((n) => n.id === route[0]) || visible[0];
  const View = active.view;

  function signOut() {
    setToken('');
    setMe(null);
  }

  return (
    <TooltipProvider>
      <SidebarProvider>
        <AppSidebar
          groups={groups}
          active={active}
          me={me}
          theme={theme}
          setTheme={setTheme}
          onSignOut={signOut}
        />
        <SidebarInset className="min-w-0">
          <header className="sticky top-0 z-10 flex h-12 items-center gap-2 border-b bg-background/85 px-3 backdrop-blur md:hidden">
            <SidebarTrigger />
            <span className="text-sm font-medium">{active.label}</span>
          </header>
          <main className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
            <View key={active.id} me={me} params={active.id === route[0] ? route.slice(1) : []} />
          </main>
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  );
}

function AppSidebar({ groups, active, me, theme, setTheme, onSignOut }) {
  const { isMobile, setOpenMobile } = useSidebar();

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" render={<a href="#/overview" />} onClick={() => setOpenMobile(false)}>
              <BrandMark className="size-8 shrink-0" />
              <span className="font-semibold tracking-tight">Open Control</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {groups.map((g) => (
          <SidebarGroup key={g.label}>
            <SidebarGroupLabel>{g.label}</SidebarGroupLabel>
            <SidebarMenu>
              {g.items.map((n) => (
                <SidebarMenuItem key={n.id}>
                  <SidebarMenuButton
                    isActive={n.id === active.id}
                    tooltip={n.label}
                    render={<a href={`#/${n.id}`} />}
                    onClick={() => setOpenMobile(false)}
                  >
                    <n.icon />
                    <span>{n.label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger render={<SidebarMenuButton size="lg" />}>
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-sidebar-accent text-sm font-semibold uppercase text-sidebar-accent-foreground">
                  {me.name.slice(0, 1)}
                </span>
                <span className="grid min-w-0 flex-1 text-left leading-tight">
                  <span className="truncate font-medium">{me.name}</span>
                  <span className="truncate text-xs text-muted-foreground capitalize">{me.role}</span>
                </span>
                <ChevronsUpDownIcon className="ml-auto" />
              </DropdownMenuTrigger>
              <DropdownMenuContent
                side={isMobile ? 'top' : 'right'}
                align="end"
                sideOffset={8}
                className="w-56"
              >
                <DropdownMenuGroup>
                  <DropdownMenuLabel>Theme</DropdownMenuLabel>
                  <DropdownMenuRadioGroup value={theme} onValueChange={setTheme}>
                    <DropdownMenuRadioItem value="system">
                      <MonitorIcon /> System
                    </DropdownMenuRadioItem>
                    <DropdownMenuRadioItem value="light">
                      <SunIcon /> Light
                    </DropdownMenuRadioItem>
                    <DropdownMenuRadioItem value="dark">
                      <MoonIcon /> Dark
                    </DropdownMenuRadioItem>
                  </DropdownMenuRadioGroup>
                </DropdownMenuGroup>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={onSignOut}>
                  <LogOutIcon /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

function Login({ onSignedIn }) {
  const [token, setTokenInput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setToken(token.trim());
    try {
      onSignedIn(await api('GET', '/whoami'));
    } catch (err) {
      setToken('');
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted/40 p-6">
      <div className="flex items-center gap-2.5">
        <BrandMark className="size-9" />
        <span className="text-lg font-semibold tracking-tight">Open Control</span>
      </div>
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>
            Paste an API token. Mint one on the server with{' '}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">
              opencontrol addtoken
            </code>
            .
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit}>
            <FieldGroup>
              <Field data-invalid={!!error || undefined}>
                <FieldLabel htmlFor="token">API token</FieldLabel>
                <Input
                  id="token"
                  type="password"
                  autoFocus
                  autoComplete="off"
                  placeholder="oc_…"
                  className="font-mono"
                  aria-invalid={!!error || undefined}
                  value={token}
                  onChange={(e) => setTokenInput(e.target.value)}
                />
                {error && <FieldError>{error}</FieldError>}
              </Field>
              <Button type="submit" size="lg" disabled={busy || !token.trim()}>
                {busy ? 'Checking…' : 'Sign in'}
              </Button>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
