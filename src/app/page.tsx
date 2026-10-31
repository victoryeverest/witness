'use client';

import { useEffect, useState, useCallback } from 'react';
import {
  Shield, Activity, AlertTriangle, FileSearch, Network, Cpu, Database,
  GitBranch, Target, FileText, Gauge, Settings, Play, Pause, Square,
  CheckCircle2, XCircle, AlertCircle, ChevronRight, Layers, Zap, Eye,
  Microscope, FileWarning, Brain, Clock, Boxes, Workflow, Flag, RefreshCw,
  ShieldCheck, ShieldAlert, Lock, Hand,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { api, getStoredCredential, setStoredCredential } from '@/lib/witness-api';
import { Input } from '@/components/ui/input';
import { Toaster } from '@/components/ui/toaster';
import { useToast } from '@/hooks/use-toast';

type Tab = 'dashboard' | 'incidents' | 'investigations' | 'evidence' | 'timeline' | 'graph' | 'hypotheses' | 'response' | 'ot' | 'benchmarks' | 'audit' | 'system';

export default function Home() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');
  const [health, setHealth] = useState<{ status: string; version: string; auth_mode?: string } | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [benchmarks, setBenchmarks] = useState<any[]>([]);
  const [agents, setAgents] = useState<any[]>([]);
  const [tools, setTools] = useState<any[]>([]);
  const [models, setModels] = useState<any>(null);
  const [selectedInvestigation, setSelectedInvestigation] = useState<string | null>(null);
  const [runningDemo, setRunningDemo] = useState(false);
  const [runningBench, setRunningBench] = useState(false);

  // Initial load
  const refreshAll = useCallback(async () => {
    try {
      const h = await api.health();
      setHealth(h);
      setConnectionError(null);
      const [invs, incs, scns, ags, tls, mds, bms] = await Promise.all([
        api.listInvestigations(),
        api.listIncidents(),
        api.availableScenarios(),
        api.listAgents(),
        api.listTools(),
        api.listModels(),
        api.listBenchmarks(),
      ]);
      setInvestigations(invs || []);
      setIncidents(incs || []);
      setScenarios(scns || []);
      setAgents(ags || []);
      setTools(tls || []);
      setModels(mds);
      setBenchmarks(bms || []);
    } catch (e: any) {
      setConnectionError(e.message);
    }
  }, []);

  useEffect(() => { refreshAll(); }, [refreshAll]);

  const runFlagship = async () => {
    setRunningDemo(true);
    try {
      const r = await api.flagshipDemo({ max_iterations: 5 });
      toast({
        title: 'Flagship demo complete',
        description: `Detection ${r.metrics.detection}, score ${r.metrics.investigation_score.toFixed(3)}, ${r.pending_approvals ?? 0} action(s) awaiting approval`,
      });
      await refreshAll();
      setSelectedInvestigation(r.investigation_id);
      setActiveTab('investigations');
    } catch (e: any) {
      toast({ title: 'Demo failed', description: e.message, variant: 'destructive' });
    } finally {
      setRunningDemo(false);
    }
  };

  const runAllBenchmarks = async () => {
    setRunningBench(true);
    try {
      const r = await api.runBenchmarks({});
      toast({
        title: 'Benchmarks complete',
        description: `${r.runs} scenarios, mean score ${r.summary.mean.investigation_score.toFixed(3)}`,
      });
      await refreshAll();
      setActiveTab('benchmarks');
    } catch (e: any) {
      toast({ title: 'Benchmarks failed', description: e.message, variant: 'destructive' });
    } finally {
      setRunningBench(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col">
      <header className="border-b border-zinc-800 bg-zinc-900/80 backdrop-blur sticky top-0 z-10">
        <div className="container mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-600/20 flex items-center justify-center border border-emerald-500/40">
              <Eye className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight">WITNESS</h1>
              <p className="text-[10px] text-zinc-500 -mt-0.5 font-mono">Evidence-Driven Autonomous Cyber Defense</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {health && (
              <Badge variant="outline" className="bg-emerald-950/40 text-emerald-400 border-emerald-500/40 font-mono text-[10px]">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse" />
                {health.status === 'ok' ? 'online' : 'offline'} · {models?.provider || 'mock'}
              </Badge>
            )}
            <Button
              size="sm"
              variant="default"
              onClick={runFlagship}
              disabled={runningDemo || runningBench}
              className="bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-semibold"
            >
              {runningDemo ? <RefreshCw className="w-3 h-3 mr-1.5 animate-spin" /> : <Play className="w-3 h-3 mr-1.5" />}
              {runningDemo ? 'Running...' : 'Run Flagship Demo'}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={runAllBenchmarks}
              disabled={runningDemo || runningBench}
              className="border-zinc-700 hover:bg-zinc-800"
            >
              {runningBench ? <RefreshCw className="w-3 h-3 mr-1.5 animate-spin" /> : <Gauge className="w-3 h-3 mr-1.5" />}
              {runningBench ? 'Benchmarking...' : 'Run Benchmarks'}
            </Button>
          </div>
        </div>
      </header>

      {connectionError && (
        <div className="container mx-auto px-4 py-2">
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Cannot connect to WITNESS backend</AlertTitle>
            <AlertDescription className="font-mono text-xs">
              {connectionError}
              <br />
              <span className="text-xs">Start it with: <code className="bg-zinc-900 px-1.5 py-0.5 rounded">cd backend &amp;&amp; python3 -m uvicorn witness.api.app:app --port 8000</code></span>
            </AlertDescription>
          </Alert>
        </div>
      )}

      <main className="container mx-auto px-4 py-4 flex-1 w-full">
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as Tab)}>
          <TabsList className="bg-zinc-900/60 border border-zinc-800 mb-4 flex flex-wrap h-auto">
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-zinc-800"><Activity className="w-3.5 h-3.5 mr-1.5" />Dashboard</TabsTrigger>
            <TabsTrigger value="incidents" className="data-[state=active]:bg-zinc-800"><AlertTriangle className="w-3.5 h-3.5 mr-1.5" />Incidents</TabsTrigger>
            <TabsTrigger value="investigations" className="data-[state=active]:bg-zinc-800"><FileSearch className="w-3.5 h-3.5 mr-1.5" />Investigations</TabsTrigger>
            <TabsTrigger value="evidence" className="data-[state=active]:bg-zinc-800"><Database className="w-3.5 h-3.5 mr-1.5" />Evidence</TabsTrigger>
            <TabsTrigger value="timeline" className="data-[state=active]:bg-zinc-800"><Clock className="w-3.5 h-3.5 mr-1.5" />Timeline</TabsTrigger>
            <TabsTrigger value="graph" className="data-[state=active]:bg-zinc-800"><GitBranch className="w-3.5 h-3.5 mr-1.5" />Attack Graph</TabsTrigger>
            <TabsTrigger value="hypotheses" className="data-[state=active]:bg-zinc-800"><Brain className="w-3.5 h-3.5 mr-1.5" />Hypotheses</TabsTrigger>
            <TabsTrigger value="response" className="data-[state=active]:bg-zinc-800"><Hand className="w-3.5 h-3.5 mr-1.5" />Response</TabsTrigger>
            <TabsTrigger value="ot" className="data-[state=active]:bg-zinc-800"><Cpu className="w-3.5 h-3.5 mr-1.5" />OT/ICS</TabsTrigger>
            <TabsTrigger value="benchmarks" className="data-[state=active]:bg-zinc-800"><Gauge className="w-3.5 h-3.5 mr-1.5" />Benchmarks</TabsTrigger>
            <TabsTrigger value="audit" className="data-[state=active]:bg-zinc-800"><Layers className="w-3.5 h-3.5 mr-1.5" />Audit</TabsTrigger>
            <TabsTrigger value="system" className="data-[state=active]:bg-zinc-800"><Settings className="w-3.5 h-3.5 mr-1.5" />System</TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard">
            <DashboardTab investigations={investigations} incidents={incidents} benchmarks={benchmarks} agents={agents} tools={tools} models={models} scenarios={scenarios} onSelectInvestigation={(id) => { setSelectedInvestigation(id); setActiveTab('investigations'); }} onRunDemo={runFlagship} runningDemo={runningDemo} />
          </TabsContent>

          <TabsContent value="incidents">
            <IncidentsTab incidents={incidents} onRefresh={refreshAll} />
          </TabsContent>

          <TabsContent value="investigations">
            <InvestigationsTab investigations={investigations} selectedId={selectedInvestigation} onSelect={setSelectedInvestigation} onRefresh={refreshAll} scenarios={scenarios} />
          </TabsContent>

          <TabsContent value="evidence">
            <EvidenceTab investigationId={selectedInvestigation} />
          </TabsContent>

          <TabsContent value="timeline">
            <TimelineTab investigationId={selectedInvestigation} />
          </TabsContent>

          <TabsContent value="graph">
            <GraphTab investigationId={selectedInvestigation} />
          </TabsContent>

          <TabsContent value="hypotheses">
            <HypothesesTab investigationId={selectedInvestigation} />
          </TabsContent>

          <TabsContent value="response">
            <ResponseTab investigationId={selectedInvestigation} authMode={health?.auth_mode} />
          </TabsContent>

          <TabsContent value="ot">
            <OTTab />
          </TabsContent>

          <TabsContent value="benchmarks">
            <BenchmarksTab benchmarks={benchmarks} onRunAll={runAllBenchmarks} runningBench={runningBench} />
          </TabsContent>

          <TabsContent value="audit">
            <AuditTab investigationId={selectedInvestigation} />
          </TabsContent>

          <TabsContent value="system">
            <SystemTab agents={agents} tools={tools} models={models} authMode={health?.auth_mode} onCredentialsChanged={refreshAll} onReset={async () => {
              try { await api.reset(); await refreshAll(); }
              catch (e: any) { toast({ title: 'Reset refused', description: e.message, variant: 'destructive' }); }
            }} />
          </TabsContent>
        </Tabs>
      </main>

      <footer className="border-t border-zinc-800 bg-zinc-900/40 mt-auto">
        <div className="container mx-auto px-4 py-2 flex items-center justify-between text-[10px] text-zinc-600 font-mono">
          <span>WITNESS v{health?.version ?? '—'} · MITRE ATT&CK Enterprise + ICS · Local-first · auth: {health?.auth_mode ?? '—'}</span>
          <span className="flex items-center gap-1">
            <Shield className="w-3 h-3" /> Don't ask the AI what happened. Make it prove what happened.
          </span>
        </div>
      </footer>
    </div>
  );
}

// ----- Dashboard -----
function DashboardTab({ investigations, incidents, benchmarks, agents, tools, models, scenarios, onSelectInvestigation, onRunDemo, runningDemo }: any) {
  const total = investigations.length;
  const active = investigations.filter((i: any) => i.status === 'active' || i.status === 'awaiting_approval').length;
  const completed = investigations.filter((i: any) => i.status === 'completed').length;
  const avgScore = benchmarks.length > 0
    ? (benchmarks.reduce((s: number, b: any) => s + (b.metrics?.investigation_score || 0), 0) / benchmarks.length)
    : 0;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard title="Investigations" value={total} icon={<FileSearch className="w-4 h-4" />} accent="emerald" />
        <StatCard title="Active" value={active} icon={<Activity className="w-4 h-4" />} accent="amber" />
        <StatCard title="Completed" value={completed} icon={<CheckCircle2 className="w-4 h-4" />} accent="emerald" />
        <StatCard title="Avg Score" value={avgScore.toFixed(3)} icon={<Gauge className="w-4 h-4" />} accent="cyan" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-zinc-100 flex items-center gap-2 text-sm">
              <Flag className="w-4 h-4 text-emerald-400" /> Flagship Demo: IT → OT Intrusion
            </CardTitle>
            <CardDescription className="text-zinc-400 text-xs">
              Per §84, the centerpiece is one continuous attack chain: phishing → PowerShell → LSASS → VPN → EWS → Modbus → process deviation.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={onRunDemo} disabled={runningDemo}
              className="bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-semibold">
              {runningDemo ? <><RefreshCw className="w-3 h-3 mr-1.5 animate-spin" />Running investigation...</>
                : <><Play className="w-3 h-3 mr-1.5" />Run flagship demo</>}
            </Button>
            <p className="text-[11px] text-zinc-500 mt-2">
              Loads the scenario, runs the central loop (§5), and evaluates against hidden ground truth (§56).
            </p>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-zinc-100 text-sm">Recent Investigations</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-64">
              {investigations.length === 0 ? (
                <p className="text-xs text-zinc-500">No investigations yet. Run the flagship demo.</p>
              ) : (
                <div className="space-y-1.5">
                  {investigations.slice(0, 10).map((i: any) => (
                    <div key={i.id}
                      onClick={() => onSelectInvestigation(i.id)}
                      className="text-xs p-2 rounded border border-zinc-800 hover:bg-zinc-800/60 cursor-pointer flex items-center justify-between gap-2">
                      <div className="flex-1 truncate">
                        <span className="font-mono text-zinc-400">{i.id}</span>{' '}
                        <span className="text-zinc-300">{i.title}</span>
                      </div>
                      <StatusBadge status={i.status} />
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardHeader><CardTitle className="text-zinc-100 text-sm flex items-center gap-2"><Brain className="w-4 h-4 text-emerald-400" />Agents</CardTitle></CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-emerald-400">{agents.length}</p>
            <p className="text-[11px] text-zinc-500">19 specialized agents per §14</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardHeader><CardTitle className="text-zinc-100 text-sm flex items-center gap-2"><Workflow className="w-4 h-4 text-cyan-400" />Tools</CardTitle></CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-cyan-400">{tools.length}</p>
            <p className="text-[11px] text-zinc-500">All tool calls go through policy engine</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardHeader><CardTitle className="text-zinc-100 text-sm flex items-center gap-2"><Boxes className="w-4 h-4 text-amber-400" />Scenarios</CardTitle></CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-amber-400">{scenarios.length}</p>
            <p className="text-[11px] text-zinc-500">Cyber range with hidden ground truth</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon, accent }: { title: string; value: any; icon: React.ReactNode; accent: string }) {
  const colorMap: Record<string, string> = {
    emerald: 'text-emerald-400 border-emerald-500/40 bg-emerald-950/20',
    amber: 'text-amber-400 border-amber-500/40 bg-amber-950/20',
    cyan: 'text-cyan-400 border-cyan-500/40 bg-cyan-950/20',
  };
  return (
    <Card className={`border ${colorMap[accent] || 'border-zinc-800 bg-zinc-900/60'} bg-opacity-20`}>
      <CardContent className="p-3">
        <div className="flex items-center justify-between">
          <span className="text-[10px] uppercase tracking-wide text-zinc-400 font-mono">{title}</span>
          {icon}
        </div>
        <p className="text-2xl font-bold mt-1">{value}</p>
      </CardContent>
    </Card>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { color: string; label: string }> = {
    active: { color: 'bg-emerald-950/40 text-emerald-400 border-emerald-500/40', label: 'Active' },
    awaiting_approval: { color: 'bg-amber-950/40 text-amber-400 border-amber-500/40', label: 'Awaiting Approval' },
    paused: { color: 'bg-zinc-800 text-zinc-300 border-zinc-700', label: 'Paused' },
    completed: { color: 'bg-cyan-950/40 text-cyan-400 border-cyan-500/40', label: 'Completed' },
    cancelled: { color: 'bg-red-950/40 text-red-400 border-red-500/40', label: 'Cancelled' },
    open: { color: 'bg-zinc-800 text-zinc-300 border-zinc-700', label: 'Open' },
    confirmed: { color: 'bg-emerald-950/40 text-emerald-400 border-emerald-500/40', label: 'Confirmed' },
    probable: { color: 'bg-amber-950/40 text-amber-400 border-amber-500/40', label: 'Probable' },
    rejected: { color: 'bg-red-950/40 text-red-400 border-red-500/40', label: 'Rejected' },
  };
  const m = map[status] || { color: 'bg-zinc-800 text-zinc-300 border-zinc-700', label: status };
  return <Badge variant="outline" className={`${m.color} text-[10px] font-mono`}>{m.label}</Badge>;
}

// ----- Incidents -----
function IncidentsTab({ incidents, onRefresh }: any) {
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader><CardTitle className="text-zinc-100 text-sm">Incidents ({incidents.length})</CardTitle></CardHeader>
      <CardContent>
        {incidents.length === 0 ? (
          <p className="text-xs text-zinc-500">No incidents. The flagship demo creates one.</p>
        ) : (
          <div className="space-y-2">
            {incidents.map((i: any) => (
              <div key={i.id} className="border border-zinc-800 rounded p-3 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-zinc-400">{i.id}</span>
                  <StatusBadge status={i.status} />
                </div>
                <div className="mt-1 text-zinc-200 font-semibold">{i.title}</div>
                {i.summary && <div className="mt-1 text-zinc-400">{i.summary}</div>}
                <div className="mt-2 flex gap-3 text-zinc-500 text-[10px] font-mono">
                  <span>severity: {i.severity}</span>
                  <span>scope: {i.scope}</span>
                  <span>detection: {(i.detection_confidence * 100).toFixed(0)}%</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ----- Investigations -----
function InvestigationsTab({ investigations, selectedId, onSelect, onRefresh, scenarios }: any) {
  const [detail, setDetail] = useState<any>(null);
  const [scenarioId, setScenarioId] = useState<string | null>(null);
  const [newTitle, setNewTitle] = useState('');
  const [newObj, setNewObj] = useState('');

  useEffect(() => {
    if (!selectedId) return;
    api.getInvestigation(selectedId).then(setDetail).catch(() => setDetail(null));
  }, [selectedId]);

  const create = async () => {
    if (!newTitle || !newObj) return;
    await api.createInvestigation({ title: newTitle, objective: newObj });
    setNewTitle(''); setNewObj('');
    onRefresh();
  };

  const run = async (id: string) => {
    // Load flagship scenario into ctx if no scenario selected
    if (!scenarioId) {
      const scn = await api.loadScenario('flagship');
      // Then create investigation-run with that scenario
      await api.runInvestigation(id, { scenario_id: scn.id, max_iterations: 5 });
    } else {
      await api.runInvestigation(id, { scenario_id: scenarioId, max_iterations: 5 });
    }
    onRefresh();
    api.getInvestigation(id).then(setDetail);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100 text-sm">Investigations ({investigations.length})</CardTitle>
          <CardDescription className="text-zinc-400 text-xs">Click to view detail. Run to execute the central loop (§5).</CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="max-h-96">
            {investigations.length === 0 ? (
              <p className="text-xs text-zinc-500">No investigations yet.</p>
            ) : (
              <div className="space-y-1.5">
                {investigations.map((i: any) => (
                  <div key={i.id}
                    onClick={() => onSelect(i.id)}
                    className={`text-xs p-2 rounded border cursor-pointer ${selectedId === i.id ? 'border-emerald-500/60 bg-emerald-950/20' : 'border-zinc-800 hover:bg-zinc-800/60'}`}>
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex-1 truncate">
                        <span className="font-mono text-zinc-400">{i.id}</span>{' '}
                        <span className="text-zinc-300">{i.title}</span>
                      </div>
                      <StatusBadge status={i.status} />
                    </div>
                    <div className="mt-1 text-[10px] text-zinc-500 truncate">{i.objective}</div>
                    <div className="mt-1 flex justify-between text-[10px] font-mono text-zinc-600">
                      <span>iter: {i.iteration}</span>
                      <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); run(i.id); }}
                        className="h-6 px-2 text-[10px] border-zinc-700">Run</Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>

          <Separator className="my-3 bg-zinc-800" />
          <div className="space-y-2">
            <div className="text-xs font-semibold text-zinc-300">New Investigation</div>
            <input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Title"
              className="w-full bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs text-zinc-100" />
            <textarea value={newObj} onChange={(e) => setNewObj(e.target.value)} placeholder="Investigation objective"
              className="w-full bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs text-zinc-100 min-h-16 resize-y" />
            <Button onClick={create} size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-zinc-950">Create</Button>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100 text-sm">Investigation Detail</CardTitle>
        </CardHeader>
        <CardContent>
          {!detail ? (
            <p className="text-xs text-zinc-500">Select an investigation to view detail.</p>
          ) : (
            <ScrollArea className="max-h-[600px]">
              <div className="space-y-3">
                <div>
                  <div className="text-[10px] font-mono text-zinc-500">{detail.id}</div>
                  <div className="text-sm font-semibold text-zinc-100">{detail.title}</div>
                  <div className="text-xs text-zinc-400">{detail.objective}</div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <StatusBadge status={detail.status} />
                  <Badge variant="outline" className="text-[10px] font-mono bg-zinc-800">iter: {detail.iteration}</Badge>
                  <Badge variant="outline" className="text-[10px] font-mono bg-zinc-800">mode: {detail.mode}</Badge>
                </div>
                {detail.final_conclusion && (
                  <Alert>
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle className="text-xs">Final Conclusion</AlertTitle>
                    <AlertDescription className="text-xs text-zinc-300">{detail.final_conclusion}</AlertDescription>
                  </Alert>
                )}
                <div>
                  <div className="text-xs font-semibold text-zinc-300 mb-2 flex items-center gap-1"><Zap className="w-3 h-3 text-emerald-400" />Evidence Coverage</div>
                  {Object.entries(detail.coverage || {}).map(([k, v]: any) => (
                    <div key={k} className="flex items-center gap-2 mb-1 text-[10px]">
                      <span className="w-20 text-zinc-400 font-mono">{k}</span>
                      <Progress value={(v as number) * 100} className="h-1.5 flex-1" />
                      <span className="w-10 text-zinc-400 font-mono">{Math.round((v as number) * 100)}%</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div className="text-xs font-semibold text-zinc-300 mb-2 flex items-center gap-1"><AlertCircle className="w-3 h-3 text-amber-400" />What Haven't We Checked? (§48)</div>
                  <div className="space-y-1">
                    {(detail.gaps || []).map((g: any, i: number) => (
                      <div key={i} className="text-[10px] p-1.5 bg-zinc-900 border border-zinc-800 rounded">
                        <span className="font-mono text-zinc-400">{g.domain}</span>{' '}
                        <span className={g.severity === 'high' ? 'text-red-400' : g.severity === 'medium' ? 'text-amber-400' : 'text-zinc-400'}>
                          {g.severity}
                        </span>{' '}
                        <span className="text-zinc-500">({Math.round(g.coverage * 100)}%)</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-xs font-semibold text-zinc-300 mb-2 flex items-center gap-1"><Brain className="w-3 h-3 text-emerald-400" />Hypotheses ({(detail.hypotheses || []).length})</div>
                  <div className="space-y-1.5">
                    {(detail.hypotheses || []).map((h: any) => (
                      <div key={h.id} className="text-[10px] p-2 border border-zinc-800 rounded">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-zinc-400">{h.id}</span>
                          <StatusBadge status={h.status} />
                        </div>
                        <div className="text-zinc-300 mt-0.5">{h.statement}</div>
                        <div className="text-zinc-500 mt-1">
                          conf: <span className="text-zinc-300">{((h.currentConfidence ?? h.current_confidence ?? 0) * 100).toFixed(0)}%</span> ·
                          support: <span className="text-emerald-400">{(h.supportEvidenceIds ?? h.support_evidence_ids ?? []).length}</span> ·
                          contradict: <span className="text-red-400">{(h.contradictEvidenceIds ?? h.contradict_evidence_ids ?? []).length}</span>
                        </div>
                        {((h.attackTechniques ?? h.attack_techniques) || []).length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {(h.attackTechniques ?? h.attack_techniques).map((t: string) => (
                              <Badge key={t} variant="outline" className="text-[9px] font-mono bg-cyan-950/40 text-cyan-400 border-cyan-500/40">{t}</Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-xs font-semibold text-zinc-300 mb-2 flex items-center gap-1"><Workflow className="w-3 h-3 text-cyan-400" />Actions ({(detail.actions || []).length})</div>
                  <div className="space-y-1">
                    {(detail.actions || []).map((a: any) => (
                      <div key={a.id} className="text-[10px] p-1.5 bg-zinc-900 border border-zinc-800 rounded">
                        <span className="font-mono text-zinc-400">{a.tool_name}</span>{' '}
                        <Badge variant="outline" className="text-[9px] font-mono">{a.status}</Badge>{' '}
                        <Badge variant="outline" className="text-[9px] font-mono">{a.risk_level}</Badge>
                      </div>
                    ))}
                    {detail.actions.length === 0 && <p className="text-[10px] text-zinc-500">No proposed actions.</p>}
                  </div>
                </div>
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ----- Evidence -----
function EvidenceTab({ investigationId }: { investigationId: string | null }) {
  const [evidence, setEvidence] = useState<any[]>([]);
  const [integrity, setIntegrity] = useState<any>(null);
  useEffect(() => {
    if (!investigationId) return;
    api.listEvidence(investigationId).then(setEvidence).catch(() => setEvidence([]));
    api.integrity(investigationId).then(setIntegrity).catch(() => setIntegrity(null));
  }, [investigationId]);
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-zinc-100 text-sm flex items-center gap-2">
          Evidence ({evidence.length})
          {integrity && (integrity.intact ? (
            <Badge variant="outline" className="text-[10px] font-mono bg-emerald-950/40 text-emerald-400 border-emerald-500/40">
              <ShieldCheck className="w-3 h-3 mr-1" />chain intact · {integrity.chained_count} linked
            </Badge>
          ) : (
            <Badge variant="outline" className="text-[10px] font-mono bg-red-950/40 text-red-400 border-red-500/40">
              <ShieldAlert className="w-3 h-3 mr-1" />integrity failure · {integrity.content_mismatches.length} altered · {integrity.chain_breaks.length} chain breaks
            </Badge>
          ))}
        </CardTitle>
        <CardDescription className="text-xs">Immutable, hash-chained evidence items per §8. {investigationId ? `Investigation: ${investigationId}` : 'Select an investigation first.'}</CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="max-h-[600px]">
          {evidence.length === 0 ? (
            <p className="text-xs text-zinc-500">No evidence collected.</p>
          ) : (
            <div className="space-y-1.5">
              {evidence.map((e: any) => (
                <div key={e.id} className="text-xs p-2 border border-zinc-800 rounded">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-zinc-400">{e.sequence != null ? `#${e.sequence} ` : ''}{e.id}</span>
                    <div className="flex gap-1.5">
                      <Badge variant="outline" className="text-[9px] font-mono bg-zinc-800">{e.source}</Badge>
                      {e.synthetic && <Badge variant="outline" className="text-[9px] font-mono bg-amber-950/40 text-amber-400 border-amber-500/40">SYNTHETIC</Badge>}
                    </div>
                  </div>
                  <div className="text-zinc-300 mt-1">
                    {e.host && <span>{e.host} · </span>}
                    {e.user && <span>{e.user} · </span>}
                    <span className="text-zinc-500">{(e.normalizedData ?? e.normalized_data)?.event_kind}</span>
                  </div>
                  <div className="text-[10px] text-zinc-500 mt-1 font-mono truncate">{e.contentHash ?? e.content_hash}</div>
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ----- Timeline -----
function TimelineTab({ investigationId }: { investigationId: string | null }) {
  const [timeline, setTimeline] = useState<any[]>([]);
  useEffect(() => {
    if (!investigationId) return;
    api.listTimeline(investigationId).then(setTimeline).catch(() => setTimeline([]));
  }, [investigationId]);
  const domainColor: Record<string, string> = {
    identity: 'text-cyan-400', endpoint: 'text-emerald-400', network: 'text-amber-400',
    ot: 'text-red-400', process: 'text-pink-400', safety: 'text-orange-400',
    persistence: 'text-purple-400', memory: 'text-blue-400', dfir: 'text-teal-400',
    c2: 'text-rose-400', cloud: 'text-indigo-400', application: 'text-lime-400',
  };
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-zinc-100 text-sm">Unified Timeline ({timeline.length})</CardTitle>
        <CardDescription className="text-xs">Cross-domain events normalized to UTC per §11. {investigationId ? `Investigation: ${investigationId}` : 'Select an investigation.'}</CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="max-h-[600px]">
          {timeline.length === 0 ? (
            <p className="text-xs text-zinc-500">No timeline events.</p>
          ) : (
            <div className="space-y-1.5">
              {timeline.map((e: any) => (
                <div key={e.id} className="text-xs p-2 border border-zinc-800 rounded flex gap-3">
                  <span className="font-mono text-zinc-500 whitespace-nowrap">{(e.timestamp || '').split('T')[1]?.split('.')[0]}</span>
                  <Badge variant="outline" className={`text-[9px] font-mono ${domainColor[e.domain] || 'text-zinc-400'} bg-zinc-900 border-zinc-700`}>{e.domain}</Badge>
                  <div className="flex-1">
                    <div className="text-zinc-300">{e.title}</div>
                    <div className="text-[10px] text-zinc-500">{e.eventType ?? e.event_type}</div>
                  </div>
                  {((e.attackTechniques ?? e.attack_techniques) || []).length > 0 && (
                    <div className="flex gap-1">
                      {(e.attackTechniques ?? e.attack_techniques).map((t: string) => (
                        <Badge key={t} variant="outline" className="text-[9px] font-mono bg-cyan-950/40 text-cyan-400 border-cyan-500/40">{t}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ----- Graph -----
function GraphTab({ investigationId }: { investigationId: string | null }) {
  const [graph, setGraph] = useState<any>(null);
  useEffect(() => {
    if (!investigationId) return;
    api.getGraph(investigationId).then(setGraph).catch(() => setGraph(null));
  }, [investigationId]);
  if (!graph) return <Card className="bg-zinc-900/60 border-zinc-800"><CardContent><p className="text-xs text-zinc-500 p-4">Select an investigation.</p></CardContent></Card>;
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-zinc-100 text-sm">Evidence Graph (§10, §29)</CardTitle>
        <CardDescription className="text-xs">{graph.nodes.length} nodes · {graph.edges.length} edges</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <div className="text-xs font-semibold text-zinc-300 mb-2">Nodes ({graph.nodes.length})</div>
            <ScrollArea className="max-h-96">
              <div className="space-y-1">
                {graph.nodes.map((n: any) => (
                  <div key={n.id} className="text-[10px] p-1.5 border border-zinc-800 rounded">
                    <div className="font-mono text-zinc-400">{n.id}</div>
                    <div className="text-zinc-300">{n.label} <Badge variant="outline" className="text-[9px] font-mono">{n.kind}</Badge></div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
          <div>
            <div className="text-xs font-semibold text-zinc-300 mb-2">Edges ({graph.edges.length})</div>
            <ScrollArea className="max-h-96">
              <div className="space-y-1">
                {graph.edges.slice(0, 200).map((e: any) => (
                  <div key={e.id} className="text-[10px] p-1.5 border border-zinc-800 rounded font-mono">
                    <span className="text-zinc-400">{e.src}</span>{' '}
                    <span className="text-emerald-400">-{e.kind}-&gt;</span>{' '}
                    <span className="text-zinc-400">{e.dst}</span>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ----- Hypotheses -----
function HypothesesTab({ investigationId }: { investigationId: string | null }) {
  const [hyps, setHyps] = useState<any[]>([]);
  const [challenge, setChallenge] = useState<any>(null);
  const [explanation, setExplanation] = useState<any>(null);
  const [explaining, setExplaining] = useState<string | null>(null);
  useEffect(() => {
    if (!investigationId) return;
    api.listHypotheses(investigationId).then(setHyps).catch(() => setHyps([]));
  }, [investigationId]);
  const explain = async (id: string) => {
    setExplaining(id);
    try { setExplanation({ id, ...(await api.explainHypothesis(id)) }); }
    catch (e: any) { setExplanation({ id, text: e.message, source: 'error' }); }
    finally { setExplaining(null); }
  };
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-zinc-100 text-sm">Hypotheses ({hyps.length})</CardTitle>
        <CardDescription className="text-xs">Each hypothesis has support/contradict evidence and confidence per §6. Click "What would change my mind?" for §49.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <ScrollArea className="max-h-96">
              <div className="space-y-2">
                {hyps.map((h: any) => (
                  <div key={h.id} className="text-xs p-2 border border-zinc-800 rounded">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-zinc-400">{h.id}</span>
                      <div className="flex gap-1.5 items-center">
                        {h.provenance?.origin === 'model' && (
                          <Badge variant="outline" title={h.provenance.rationale}
                            className="text-[9px] font-mono bg-violet-950/40 text-violet-300 border-violet-500/40">
                            <Brain className="w-3 h-3 mr-1" />model-proposed
                          </Badge>
                        )}
                        <StatusBadge status={h.status} />
                      </div>
                    </div>
                    <div className="text-zinc-300 mt-1">{h.statement}</div>
                    {h.provenance?.origin === 'model' && (
                      <div className="text-[10px] text-violet-300/80 mt-1">
                        {h.provenance.model}: {h.provenance.rationale}
                        <span className="text-zinc-500"> · confidence is set by evidence linking, not by the model</span>
                      </div>
                    )}
                    <div className="text-[10px] text-zinc-500 mt-1">
                      conf: <span className="text-zinc-300">{((h.currentConfidence ?? h.current_confidence ?? 0) * 100).toFixed(0)}%</span> ·
                      support: <span className="text-emerald-400">{(h.supportEvidenceIds ?? h.support_evidence_ids ?? []).length}</span> ·
                      contradict: <span className="text-red-400">{(h.contradictEvidenceIds ?? h.contradict_evidence_ids ?? []).length}</span>
                    </div>
                    <Button size="sm" variant="outline" className="mt-1 h-6 text-[10px] border-zinc-700"
                      onClick={async () => {
                        const c = await api.challengeHypothesis(investigationId!, h.id);
                        setChallenge(c);
                      }}>
                      What would change my mind?
                    </Button>
                    <Button size="sm" variant="outline" className="mt-1 ml-1.5 h-6 text-[10px] border-zinc-700"
                      disabled={explaining !== null} onClick={() => explain(h.id)}>
                      {explaining === h.id ? <RefreshCw className="w-3 h-3 mr-1 animate-spin" /> : null}
                      Why do we believe this?
                    </Button>
                    {explanation?.id === h.id && (
                      <div className="mt-2 p-2 rounded border border-zinc-700 bg-zinc-950/60 text-zinc-300">
                        <div className="text-[10px] font-mono text-zinc-500 mb-1">
                          {explanation.source === 'model'
                            ? `${explanation.model} · citations verified against evidence`
                            : explanation.source === 'deterministic'
                              ? `rule-based explanation${explanation.model_unavailable_reason ? ` (model output not used: ${explanation.model_unavailable_reason})` : ''}`
                              : 'error'}
                        </div>
                        {explanation.text}
                      </div>
                    )}
                  </div>
                ))}
                {hyps.length === 0 && <p className="text-xs text-zinc-500">No hypotheses.</p>}
              </div>
            </ScrollArea>
          </div>
          <div>
            <div className="text-xs font-semibold text-zinc-300 mb-2">Counter-evidence Challenge (§49)</div>
            {challenge ? (
              <div className="text-xs space-y-2 p-2 border border-zinc-800 rounded">
                <div><span className="text-zinc-500">Hypothesis:</span> {challenge.current_conclusion}</div>
                <div><span className="text-zinc-500">Confidence:</span> {(challenge.current_confidence * 100).toFixed(0)}%</div>
                <div>
                  <div className="text-zinc-500 mb-1">Strongest supporting:</div>
                  <div className="font-mono text-emerald-400">{challenge.strongest_supporting?.join(', ') || '(none)'}</div>
                </div>
                <div>
                  <div className="text-zinc-500 mb-1">Strongest contradicting:</div>
                  <div className="font-mono text-red-400">{challenge.strongest_contradicting?.join(', ') || '(none)'}</div>
                </div>
                <div>
                  <div className="text-zinc-500 mb-1">Missing evidence:</div>
                  <div className="font-mono text-amber-400">{challenge.missing_evidence?.map((m: any) => m.description || JSON.stringify(m)).join('; ') || '(none)'}</div>
                </div>
                <div>
                  <div className="text-zinc-500 mb-1">What would reduce confidence:</div>
                  <ul className="list-disc ml-4 text-zinc-300">
                    {challenge.would_reduce_confidence?.map((r: string, i: number) => <li key={i}>{r}</li>)}
                  </ul>
                </div>
              </div>
            ) : (
              <p className="text-xs text-zinc-500">Click "What would change my mind?" on a hypothesis.</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ----- OT -----
function OTTab() {
  const [assets, setAssets] = useState<any[]>([]);
  const [assessment, setAssessment] = useState<any>(null);
  const [tool, setTool] = useState('isolate_endpoint');
  const [host, setHost] = useState('EWS-01');
  useEffect(() => { api.listOtAssets().then(setAssets).catch(() => setAssets([])); }, []);
  const assess = async () => {
    const a = await api.otSafetyAssessment({ tool_name: tool, arguments: { host } });
    setAssessment(a);
  };
  return (
    <div className="space-y-3">
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100 text-sm flex items-center gap-2"><Cpu className="w-4 h-4 text-red-400" />OT Safety Engine (§25)</CardTitle>
          <CardDescription className="text-xs">
            The signature feature: WITNESS refuses to autonomously isolate PLCs because cyber containment could interrupt safety-critical processes (§88).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2 items-end mb-3">
            <div>
              <div className="text-[10px] text-zinc-500 mb-1">Action</div>
              <select value={tool} onChange={(e) => setTool(e.target.value)}
                className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs text-zinc-100">
                <option value="isolate_endpoint">isolate_endpoint</option>
                <option value="disable_account">disable_account</option>
                <option value="plc_control_action">plc_control_action</option>
              </select>
            </div>
            <div>
              <div className="text-[10px] text-zinc-500 mb-1">Host</div>
              <select value={host} onChange={(e) => setHost(e.target.value)}
                className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs text-zinc-100">
                <option value="EWS-01">EWS-01 (Engineering Workstation)</option>
                <option value="SCADA-01">SCADA-01</option>
                <option value="HMI-01">HMI-01</option>
                <option value="PLC-01">PLC-01</option>
                <option value="PLC-07">PLC-07</option>
              </select>
            </div>
            <Button onClick={assess} size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-zinc-950">Assess</Button>
          </div>
          {assessment && (
            <div className="text-xs space-y-2 p-3 border border-zinc-800 rounded bg-zinc-950">
              <div className="flex items-center justify-between">
                <span className="text-zinc-400">Classification:</span>
                <Badge variant="outline" className={`text-[10px] font-mono ${assessment.classification === 'prohibited' ? 'bg-red-950/40 text-red-400 border-red-500/40' : assessment.classification === 'safety_critical' ? 'bg-orange-950/40 text-orange-400 border-orange-500/40' : 'bg-amber-950/40 text-amber-400 border-amber-500/40'}`}>
                  {assessment.classification}
                </Badge>
              </div>
              <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
                <div><span className="text-zinc-500">cyber_risk:</span> <span className="text-zinc-300">{assessment.cyber_risk}</span></div>
                <div><span className="text-zinc-500">operational_risk:</span> <span className="text-zinc-300">{assessment.operational_risk}</span></div>
                <div><span className="text-zinc-500">safety_dependency:</span> <span className="text-zinc-300">{assessment.safety_dependency}</span></div>
                <div><span className="text-zinc-500">reversibility:</span> <span className="text-zinc-300">{assessment.reversibility}</span></div>
                <div><span className="text-zinc-500">physical_consequence:</span> <span className="text-zinc-300">{assessment.physical_consequence || '—'}</span></div>
                <div><span className="text-zinc-500">requires_human_ot_authority:</span> <span className="text-zinc-300">{String(assessment.requires_human_ot_authority)}</span></div>
              </div>
              <div className="pt-2 border-t border-zinc-800">
                <div className="text-zinc-500 text-[10px] mb-1">Rationale:</div>
                <div className="text-zinc-300">{assessment.rationale}</div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader><CardTitle className="text-zinc-100 text-sm">OT Assets ({assets.length})</CardTitle></CardHeader>
        <CardContent>
          <ScrollArea className="max-h-72">
            <div className="space-y-1.5">
              {assets.map((a: any) => (
                <div key={a.id} className="text-xs p-2 border border-zinc-800 rounded">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-zinc-400">{a.asset_id}</span>
                    <Badge variant="outline" className="text-[9px] font-mono bg-red-950/40 text-red-400 border-red-500/40">{a.ot_type}</Badge>
                  </div>
                  <div className="text-[10px] text-zinc-500 mt-0.5">
                    protocol: {a.protocol || '—'} · firmware: {a.firmware || '—'} · process: {a.physical_process || '—'} · safety_impact: {a.safety_impact || '—'}
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

// ----- Response (human approval) -----
const SCOPES = ['security', 'ot_engineering', 'process_owner'] as const;

function statusStyle(status: string) {
  switch (status) {
    case 'completed': return 'bg-emerald-950/40 text-emerald-400 border-emerald-500/40';
    case 'approved': return 'bg-cyan-950/40 text-cyan-400 border-cyan-500/40';
    case 'proposed': return 'bg-amber-950/40 text-amber-400 border-amber-500/40';
    case 'prohibited':
    case 'denied':
    case 'rejected':
    case 'failed': return 'bg-red-950/40 text-red-400 border-red-500/40';
    default: return 'bg-zinc-800 text-zinc-300 border-zinc-700';
  }
}

function ResponseTab({ investigationId, authMode }: { investigationId: string | null; authMode?: string }) {
  const { toast } = useToast();
  const [actions, setActions] = useState<any[]>([]);
  // The page is client-only (useState initializers run in the browser), so
  // stored credentials can be read once at mount instead of in an effect.
  const [approver, setApprover] = useState(() => getStoredCredential('witness.user'));
  const [busy, setBusy] = useState<string | null>(null);
  const tokenMode = authMode === 'token';

  const load = useCallback(async () => {
    if (!investigationId) return;
    try { setActions(await api.listActions(investigationId)); }
    catch { setActions([]); }
  }, [investigationId]);
  useEffect(() => { load(); }, [load]);

  const act = async (key: string, fn: () => Promise<any>, ok: string) => {
    setBusy(key);
    try {
      await fn();
      toast({ title: ok });
      await load();
    } catch (e: any) {
      toast({ title: 'Refused by policy', description: e.message, variant: 'destructive' });
    } finally {
      setBusy(null);
    }
  };
  const identity = tokenMode ? {} : { approver_id: approver || undefined };

  if (!investigationId) {
    return <p className="text-xs text-zinc-500">Select an investigation first.</p>;
  }
  return (
    <div className="space-y-3">
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100 text-sm flex items-center gap-2"><Lock className="w-4 h-4 text-emerald-400" />Response actions (§37, §69)</CardTitle>
          <CardDescription className="text-xs">
            Agents only propose. Every side-effecting action waits for human sign-off on each required scope,
            by a different person per scope. Prohibited and denied actions can never run.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-2">
          {tokenMode ? (
            <span className="text-xs text-zinc-400">Signing as the identity bound to your API token.</span>
          ) : (
            <>
              <span className="text-xs text-zinc-400">Sign as</span>
              <Input value={approver} onChange={(e) => { setApprover(e.target.value); setStoredCredential('witness.user', e.target.value.trim()); }} placeholder="your user id"
                className="h-7 w-48 text-xs bg-zinc-950 border-zinc-700" />
              <span className="text-[10px] text-amber-400">dev mode: identity is not verified</span>
            </>
          )}
          <Button size="sm" variant="outline" className="h-7 border-zinc-700 ml-auto" onClick={load}>
            <RefreshCw className="w-3 h-3 mr-1.5" />Refresh
          </Button>
        </CardContent>
      </Card>

      {actions.length === 0 && <p className="text-xs text-zinc-500">No actions proposed for this investigation.</p>}
      {actions.map((a: any) => {
        const required = (a.approval_scope || '').split(',').filter(Boolean);
        const signed = new Map<string, any>(
          (a.approvals || []).filter((x: any) => x.status === 'approved').map((x: any) => [x.role, x]));
        return (
          <Card key={a.id} className="bg-zinc-900/60 border-zinc-800">
            <CardContent className="pt-4 space-y-2 text-xs">
              <div className="flex items-center justify-between gap-2">
                <div className="font-mono">
                  <span className="text-zinc-100">{a.tool_name}</span>{' '}
                  <span className="text-zinc-400">{JSON.stringify(a.arguments)}</span>
                </div>
                <div className="flex gap-1.5">
                  <Badge variant="outline" className="text-[10px] font-mono bg-zinc-800 text-zinc-300 border-zinc-700">risk: {a.risk_level}</Badge>
                  <Badge variant="outline" className={`text-[10px] font-mono ${statusStyle(a.status)}`}>{a.status}</Badge>
                </div>
              </div>
              {a.blast_radius?.rationale && <p className="text-zinc-400">{a.blast_radius.rationale}</p>}
              {a.result?.notes?.length > 0 && <p className="text-red-400">{a.result.notes.join(' ')}</p>}
              <div className="text-[10px] text-zinc-500 font-mono">proposed by {a.proposed_by} · {a.reversibility}</div>
              {required.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {SCOPES.filter((sc) => required.includes(sc)).map((sc) => {
                    const sig = signed.get(sc);
                    return sig ? (
                      <Badge key={sc} variant="outline" className="text-[10px] font-mono bg-emerald-950/40 text-emerald-400 border-emerald-500/40">
                        <CheckCircle2 className="w-3 h-3 mr-1" />{sc}: {sig.approver_id}
                      </Badge>
                    ) : a.status === 'proposed' ? (
                      <Button key={sc} size="sm" variant="outline" disabled={busy !== null}
                        className="h-6 text-[10px] border-zinc-700"
                        onClick={() => act(`${a.id}:${sc}`, () => api.approveAction({ action_id: a.id, approver_role: sc, ...identity }), `Signed ${sc}`)}>
                        Sign {sc}
                      </Button>
                    ) : (
                      <Badge key={sc} variant="outline" className="text-[10px] font-mono bg-zinc-800 text-zinc-400 border-zinc-700">{sc}: unsigned</Badge>
                    );
                  })}
                </div>
              )}
              <div className="flex gap-2">
                {a.status === 'proposed' && (
                  <Button size="sm" variant="outline" disabled={busy !== null} className="h-7 border-red-800 text-red-400"
                    onClick={() => act(`${a.id}:reject`, () => api.rejectAction({
                      action_id: a.id, approver_role: required[0] || 'security', reason: 'Rejected from console', ...identity,
                    }), 'Action rejected')}>
                    <XCircle className="w-3 h-3 mr-1.5" />Reject
                  </Button>
                )}
                {a.status === 'approved' && (
                  <Button size="sm" disabled={busy !== null} className="h-7 bg-emerald-600 hover:bg-emerald-500 text-zinc-950"
                    onClick={() => act(`${a.id}:exec`, () => api.executeAction({ action_id: a.id }), 'Action executed')}>
                    <Play className="w-3 h-3 mr-1.5" />Execute
                  </Button>
                )}
              </div>
              {a.verification && (
                <div className={`p-2 rounded border ${a.verification.verified ? 'border-emerald-800 text-emerald-400' : 'border-red-800 text-red-400'}`}>
                  Verification: {a.verification.verified === null ? 'not verifiable' : a.verification.verified ? 'passed' : 'FAILED'}
                  {(a.verification.checks || []).map((c: any) => (
                    <div key={c.check} className="text-[10px] font-mono text-zinc-400">{c.passed ? '✓' : '✗'} {c.detail}</div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ----- Benchmarks -----
function BenchmarksTab({ benchmarks, onRunAll, runningBench }: any) {
  const meanScore = benchmarks.length > 0
    ? benchmarks.reduce((s: number, b: any) => s + (b.metrics?.investigation_score || 0), 0) / benchmarks.length
    : 0;
  const meanDetection = benchmarks.length > 0
    ? benchmarks.reduce((s: number, b: any) => s + (b.metrics?.detection || 0), 0) / benchmarks.length
    : 0;
  const meanHallucination = benchmarks.length > 0
    ? benchmarks.reduce((s: number, b: any) => s + (b.metrics?.hallucination_rate || 0), 0) / benchmarks.length
    : 0;
  return (
    <div className="space-y-3">
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100 text-sm flex items-center gap-2"><Gauge className="w-4 h-4 text-emerald-400" />WITNESS-Bench (§57-§60)</CardTitle>
          <CardDescription className="text-xs">Evidence-backed evaluation against hidden ground truth. Mean scores across {benchmarks.length} runs.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
            <StatCard title="Mean Score" value={meanScore.toFixed(3)} icon={<Gauge className="w-4 h-4" />} accent="emerald" />
            <StatCard title="Detection" value={`${(meanDetection * 100).toFixed(0)}%`} icon={<Target className="w-4 h-4" />} accent="cyan" />
            <StatCard title="Hallucination" value={`${(meanHallucination * 100).toFixed(1)}%`} icon={<FileWarning className="w-4 h-4" />} accent="amber" />
            <StatCard title="Runs" value={benchmarks.length} icon={<Microscope className="w-4 h-4" />} accent="emerald" />
          </div>
          <Button onClick={onRunAll} disabled={runningBench}
            className="bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-semibold">
            {runningBench ? <><RefreshCw className="w-3 h-3 mr-1.5 animate-spin" />Running all scenarios...</>
              : <><Play className="w-3 h-3 mr-1.5" />Run all benchmarks</>}
          </Button>
        </CardContent>
      </Card>

      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader><CardTitle className="text-zinc-100 text-sm">Per-scenario results</CardTitle></CardHeader>
        <CardContent>
          <ScrollArea className="max-h-96">
            <div className="space-y-2">
              {benchmarks.map((b: any) => (
                <div key={b.id} className="text-xs p-2 border border-zinc-800 rounded">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-zinc-400">{b.scenario_id}</span>
                    <Badge variant="outline" className="text-[10px] font-mono bg-zinc-800">{b.model_name}</Badge>
                  </div>
                  <div className="mt-2 grid grid-cols-4 gap-2 text-[10px] font-mono">
                    <Metric label="score" value={(b.metrics?.investigation_score || 0).toFixed(3)} good />
                    <Metric label="detect_ok" value={String(b.metrics?.detection_correct ?? 0)} good />
                    <Metric label="atk_acc" value={(b.metrics?.attack_technique_accuracy || 0).toFixed(3)} good />
                    <Metric label="halluc" value={(b.metrics?.hallucination_rate || 0).toFixed(3)} bad />
                  </div>
                  <div className="mt-2 grid grid-cols-4 gap-2 text-[10px] font-mono">
                    <Metric label="evidence" value={String(b.metrics?.evidence_count || 0)} />
                    <Metric label="hypotheses" value={String(b.metrics?.hypotheses_count || 0)} />
                    <Metric label="ev_backed" value={(b.metrics?.evidence_backed_accuracy || 0).toFixed(2)} good />
                    <Metric label="latency" value={(b.metrics?.latency_seconds || 0).toFixed(2) + 's'} />
                  </div>
                </div>
              ))}
              {benchmarks.length === 0 && <p className="text-xs text-zinc-500">No benchmark runs yet. Click "Run all benchmarks".</p>}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

function Metric({ label, value, good, bad }: { label: string; value: string; good?: boolean; bad?: boolean }) {
  const color = good ? 'text-emerald-400' : bad ? 'text-red-400' : 'text-zinc-300';
  return (
    <div>
      <span className="text-zinc-500">{label}:</span> <span className={color}>{value}</span>
    </div>
  );
}

// ----- Audit -----
function AuditTab({ investigationId }: { investigationId: string | null }) {
  const [audit, setAudit] = useState<any[]>([]);
  useEffect(() => {
    api.listAudit(investigationId || undefined, 200).then(setAudit).catch(() => setAudit([]));
  }, [investigationId]);
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-zinc-100 text-sm">Audit Log ({audit.length})</CardTitle>
        <CardDescription className="text-xs">Every meaningful agent / tool / policy action per §43. {investigationId ? `Filter: ${investigationId}` : 'All investigations.'}</CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="max-h-[600px]">
          <div className="space-y-1">
            {audit.map((a: any) => (
              <div key={a.id} className="text-[10px] p-1.5 border border-zinc-800 rounded font-mono">
                <span className="text-zinc-500">{a.timestamp?.split('T')[1]?.split('.')[0]}</span>{' '}
                <span className="text-emerald-400">{a.actor}</span>{' '}
                {a.tool && <span className="text-cyan-400">{a.tool}</span>}
                {a.policy_decision && <span className="text-amber-400">[{a.policy_decision}]</span>}
                <div className="text-zinc-500 ml-2">{JSON.stringify(a.result || {}).slice(0, 80)}</div>
              </div>
            ))}
            {audit.length === 0 && <p className="text-xs text-zinc-500">No audit entries.</p>}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ----- System -----
function SystemTab({ agents, tools, models, onReset, authMode, onCredentialsChanged }: any) {
  const [attackEnt, setAttackEnt] = useState<any>(null);
  const [attackIcs, setAttackIcs] = useState<any>(null);
  const [token, setToken] = useState(() => getStoredCredential('witness.token'));
  const [user, setUser] = useState(() => getStoredCredential('witness.user'));
  const [whoami, setWhoami] = useState<any>(null);
  const refreshWhoami = () => api.whoami().then(setWhoami).catch(() => setWhoami(null));
  useEffect(() => {
    api.attackEnterprise().then(setAttackEnt).catch(() => {});
    api.attackIcs().then(setAttackIcs).catch(() => {});
    refreshWhoami();
  }, []);
  const saveCredentials = async () => {
    setStoredCredential('witness.token', token.trim());
    setStoredCredential('witness.user', user.trim());
    await refreshWhoami();
    await onCredentialsChanged?.();
  };
  return (
    <div className="space-y-3">
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100 text-sm flex items-center gap-2"><Lock className="w-4 h-4 text-emerald-400" />Identity</CardTitle>
          <CardDescription className="text-xs">
            Backend auth mode: <span className="font-mono">{authMode ?? 'unknown'}</span>.
            {authMode === 'token'
              ? ' Paste the API token issued to you; your identity and role come from it.'
              : ' Development mode: no credentials are checked. Set a user id so approvals are attributed.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-2 text-xs">
          {authMode === 'token' ? (
            <Input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="API token"
              className="h-7 w-72 bg-zinc-950 border-zinc-700" />
          ) : (
            <Input value={user} onChange={(e) => setUser(e.target.value)} placeholder="user id"
              className="h-7 w-48 bg-zinc-950 border-zinc-700" />
          )}
          <Button size="sm" variant="outline" className="h-7 border-zinc-700" onClick={saveCredentials}>Save</Button>
          {whoami && (
            <span className="font-mono text-zinc-400">
              signed in as {whoami.user_id} ({whoami.role ?? 'no role'}){whoami.authenticated ? ' · verified' : ' · unverified'}
            </span>
          )}
        </CardContent>
      </Card>
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100 text-sm">System</CardTitle>
          <CardDescription className="text-xs">Model layer, agents, tools, ATT&CK coverage.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div>
              <div className="font-semibold text-zinc-300 mb-1">Models (§16)</div>
              {models && (
                <div className="text-[11px] space-y-0.5 font-mono">
                  <div><span className="text-zinc-500">provider:</span> {models.provider}</div>
                  <div><span className="text-zinc-500">small:</span> {models.small}</div>
                  <div><span className="text-zinc-500">medium:</span> {models.medium}</div>
                  <div><span className="text-zinc-500">strong:</span> {models.strong}</div>
                  <div><span className="text-zinc-500">privacy_mode:</span> {models.privacy_mode}</div>
                </div>
              )}
            </div>
            <div>
              <div className="font-semibold text-zinc-300 mb-1">Agents ({agents.length})</div>
              <div className="text-[11px] space-y-0.5">
                {agents.map((a: any) => (
                  <div key={a.name} className="font-mono text-zinc-400">{a.name}</div>
                ))}
              </div>
            </div>
            <div>
              <div className="font-semibold text-zinc-300 mb-1">Tools ({tools.length})</div>
              <div className="text-[11px] space-y-0.5">
                {tools.map((t: any) => (
                  <div key={t.name} className="font-mono">
                    <span className="text-zinc-400">{t.name}</span>{' '}
                    <Badge variant="outline" className="text-[9px] bg-zinc-800">{t.risk_level}</Badge>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <Separator className="my-3 bg-zinc-800" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <div className="text-xs font-semibold text-zinc-300 mb-1">MITRE ATT&CK Enterprise ({attackEnt?.techniques ? Object.keys(attackEnt.techniques).length : 0})</div>
              <div className="text-[10px] font-mono text-zinc-400 max-h-40 overflow-y-auto">
                {attackEnt?.techniques && Object.entries(attackEnt.techniques).map(([k, v]) => (
                  <div key={k}><span className="text-cyan-400">{k}</span> {String(v)}</div>
                ))}
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold text-zinc-300 mb-1">MITRE ATT&CK ICS ({attackIcs?.techniques ? Object.keys(attackIcs.techniques).length : 0})</div>
              <div className="text-[10px] font-mono text-zinc-400 max-h-40 overflow-y-auto">
                {attackIcs?.techniques && Object.entries(attackIcs.techniques).map(([k, v]) => (
                  <div key={k}><span className="text-red-400">{k}</span> {String(v)}</div>
                ))}
              </div>
            </div>
          </div>
          <Separator className="my-3 bg-zinc-800" />
          <Button onClick={onReset} variant="outline" size="sm" className="border-red-500/40 text-red-400 hover:bg-red-950/40">
            <RefreshCw className="w-3 h-3 mr-1.5" />Reset database (drops all data)
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
