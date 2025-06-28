'use client';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Badge, type BadgeProps } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AlertCircle, KeyRound, ShieldOff, ArrowLeft, FileText, Cpu, ShieldCheck, ListTree, Router, Camera, MemoryStick, Printer, HelpCircle } from 'lucide-react';
import type { AnalyzeFirmwareOutput } from '@/ai/flows/analyze-firmware';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';


const getBadgeVariantForCvss = (score: number): BadgeProps['variant'] => {
  if (score >= 9.0) return 'destructive';
  if (score >= 7.0) return 'destructive'; // No orange by default, use destructive for High
  if (score >= 4.0) return 'secondary';
  return 'outline';
};

const DeviceTypeIcon = ({ type }: { type: string }) => {
    const lowerType = type.toLowerCase();
    if (lowerType.includes('router')) return <Router className="h-4 w-4 text-muted-foreground" />;
    if (lowerType.includes('camera')) return <Camera className="h-4 w-4 text-muted-foreground" />;
    if (lowerType.includes('iot') || lowerType.includes('sensor')) return <MemoryStick className="h-4 w-4 text-muted-foreground" />;
    if (lowerType.includes('printer')) return <Printer className="h-4 w-4 text-muted-foreground" />;
    return <HelpCircle className="h-4 w-4 text-muted-foreground" />;
};


export function AnalysisReport({ analysis, onReset }: { analysis: AnalyzeFirmwareOutput, onReset: () => void }) {
  const { overallSummary, firmwareType, bootlogAnalysis, cves, secrets, unsafeApis, sbom } = analysis;

  const totalIssues = cves.length + secrets.length + unsafeApis.length;

  return (
    <div className="w-full space-y-6 animate-in fade-in-50">
      <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground font-headline">Analysis Report</h1>
            <p className="text-muted-foreground">A summary of the security posture of your firmware.</p>
        </div>
        <Button onClick={onReset} variant="outline">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Analyze New Files
        </Button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Issues</CardTitle>
                <AlertCircle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
                <div className="text-2xl font-bold">{totalIssues}</div>
                <p className="text-xs text-muted-foreground">
                    {cves.length} CVEs, {secrets.length} secrets, {unsafeApis.length} unsafe APIs
                </p>
            </CardContent>
        </Card>
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Device Type</CardTitle>
                <DeviceTypeIcon type={firmwareType.type} />
            </CardHeader>
            <CardContent>
                <div className="text-2xl font-bold">{firmwareType.type}</div>
                <p className="text-xs text-muted-foreground">
                    Confidence: {(firmwareType.confidence * 100).toFixed(0)}%
                </p>
            </CardContent>
        </Card>
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Kernel Version</CardTitle>
                <Cpu className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
                <div className="text-2xl font-bold">{bootlogAnalysis.kernelVersion || "Not Found"}</div>
                <p className="text-xs text-muted-foreground">Detected from bootlog</p>
            </CardContent>
        </Card>
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Security Posture</CardTitle>
                <ShieldCheck className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
                <div className="text-2xl font-bold">Review Needed</div>
                 <p className="text-xs text-muted-foreground">Based on automated analysis</p>
            </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Overall Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">{overallSummary}</p>
          {firmwareType.reasoning && (
             <p className="text-sm text-muted-foreground mt-2 pt-2 border-t border-border/50">
                <span className="font-semibold text-foreground">Classification Rationale:</span> {firmwareType.reasoning}
              </p>
            )}
        </CardContent>
      </Card>
      
      <Accordion type="multiple" defaultValue={['cves', 'secrets', 'unsafe-apis', 'sbom', 'bootlog']} className="w-full space-y-4">
        
        <Card>
          <AccordionItem value="cves" className="border-b-0">
            <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                <div className="flex items-center gap-3">
                    <AlertCircle className="h-6 w-6 text-destructive" />
                    <span>CVEs Found</span>
                    <Badge variant="destructive">{cves.length}</Badge>
                </div>
            </AccordionTrigger>
            <AccordionContent className="px-6 pb-6">
                <div className="space-y-4">
                    {cves.length > 0 ? cves.map((cve) => (
                        <Card key={cve.cveId} className="bg-muted/30">
                            <CardHeader>
                                <div className="flex justify-between items-start">
                                    <CardTitle className="text-base">{cve.cveId}</CardTitle>
                                    <Badge variant={getBadgeVariantForCvss(cve.cvssScore)}>CVSS: {cve.cvssScore.toFixed(1)}</Badge>
                                </div>
                                <CardDescription className="pt-2">{cve.description}</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <h4 className="font-semibold mb-2 text-sm">Summary:</h4>
                                <div className="pl-4 border-l-2 border-primary/50 space-y-1">
                                {cve.summary.split('\n').map((line, i) => (
                                    line.trim() && <p key={i} className="text-sm text-muted-foreground">{line.replace(/^- /, '• ')}</p>
                                ))}
                                </div>
                            </CardContent>
                        </Card>
                    )) : <p className="text-muted-foreground">No CVEs were automatically identified.</p>}
                </div>
            </AccordionContent>
          </AccordionItem>
        </Card>
        
        <Card>
          <AccordionItem value="secrets" className="border-b-0">
            <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                <div className="flex items-center gap-3">
                    <KeyRound className="h-6 w-6 text-accent" />
                    <span>Hardcoded Secrets</span>
                    <Badge variant="secondary" className="bg-accent text-accent-foreground">{secrets.length}</Badge>
                </div>
            </AccordionTrigger>
            <AccordionContent className="px-6 pb-6">
                 <div className="space-y-4">
                    {secrets.length > 0 ? secrets.map((secret, i) => (
                        <Card key={i} className="bg-muted/30">
                            <CardHeader>
                                <CardTitle className="text-base">{secret.type}</CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                                <p className="text-sm text-muted-foreground font-mono break-all bg-background p-2 rounded-md">{secret.value}</p>
                                <p className="text-sm"><span className="font-semibold">Recommendation:</span> {secret.recommendation}</p>
                            </CardContent>
                        </Card>
                    )) : <p className="text-muted-foreground">No hardcoded secrets were detected.</p>}
                </div>
            </AccordionContent>
          </AccordionItem>
        </Card>

        <Card>
          <AccordionItem value="unsafe-apis" className="border-b-0">
            <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                <div className="flex items-center gap-3">
                    <ShieldOff className="h-6 w-6 text-primary" />
                    <span>Unsafe API Usage</span>
                    <Badge>{unsafeApis.length}</Badge>
                </div>
            </AccordionTrigger>
            <AccordionContent className="px-6 pb-6">
                 <div className="space-y-4">
                    {unsafeApis.length > 0 ? unsafeApis.map((api, i) => (
                        <Card key={i} className="bg-muted/30">
                            <CardHeader>
                                <CardTitle className="text-base font-mono">{api.functionName}</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">{api.reason}</p>
                            </CardContent>
                        </Card>
                    )) : <p className="text-muted-foreground">No strings indicating unsafe API usage were found.</p>}
                </div>
            </AccordionContent>
          </AccordionItem>
        </Card>

        <Card>
          <AccordionItem value="sbom" className="border-b-0">
            <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                <div className="flex items-center gap-3">
                    <ListTree className="h-6 w-6 text-[hsl(var(--chart-2))]" />
                    <span>Software Bill of Materials (SBOM)</span>
                    <Badge variant="secondary">{sbom.length}</Badge>
                </div>
            </AccordionTrigger>
            <AccordionContent className="px-6 pb-6">
                {sbom && sbom.length > 0 ? (
                    <Card>
                        <Table>
                        <TableHeader>
                            <TableRow>
                            <TableHead>Name</TableHead>
                            <TableHead>Version</TableHead>
                            <TableHead>Type</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {sbom.map((component, i) => (
                            <TableRow key={i}>
                                <TableCell className="font-medium">{component.name}</TableCell>
                                <TableCell>{component.version}</TableCell>
                                <TableCell>{component.type}</TableCell>
                            </TableRow>
                            ))}
                        </TableBody>
                        </Table>
                    </Card>
                ) : <p className="text-muted-foreground">No software components were identified to generate an SBOM.</p>}
            </AccordionContent>
          </AccordionItem>
        </Card>

        <Card>
          <AccordionItem value="bootlog" className="border-b-0">
            <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                <div className="flex items-center gap-3">
                    <FileText className="h-6 w-6 text-muted-foreground" />
                    <span>Bootlog Analysis</span>
                </div>
            </AccordionTrigger>
            <AccordionContent className="px-6 pb-6 space-y-4">
                <div>
                  <h4 className="font-semibold mb-1">Detected Hardware</h4>
                  {bootlogAnalysis.hardware.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                        {bootlogAnalysis.hardware.map((hw, i) => <Badge key={i} variant="outline">{hw}</Badge>)}
                    </div>
                  ) : <p className="text-sm text-muted-foreground">No specific hardware detected.</p>}
                </div>
                 <div>
                  <h4 className="font-semibold mb-1">Detected Modules/Drivers</h4>
                  {bootlogAnalysis.modules && bootlogAnalysis.modules.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                        {bootlogAnalysis.modules.map((mod, i) => <Badge key={i} variant="secondary">{mod}</Badge>)}
                    </div>
                  ) : <p className="text-sm text-muted-foreground">No modules or drivers detected.</p>}
                </div>
                <div>
                  <h4 className="font-semibold mb-1">Analysis Summary</h4>
                  <p className="text-sm text-muted-foreground">{bootlogAnalysis.summary}</p>
                </div>
            </AccordionContent>
          </AccordionItem>
        </Card>
      </Accordion>
    </div>
  );
}
