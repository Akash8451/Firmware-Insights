'use client';
import * as React from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Badge, type BadgeProps } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AlertCircle, KeyRound, ShieldOff, ArrowLeft, FileText, Cpu, ShieldCheck, ListTree, Router, Camera, MemoryStick, Printer, HelpCircle, FolderTree, FileCode, Download, ShieldAlert } from 'lucide-react';
import type { AnalyzeFirmwareOutput } from '@/ai/flows/analyze-firmware';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltipContent } from "@/components/ui/chart";


const getBadgeVariantForCvss = (score: number): BadgeProps['variant'] => {
  if (score >= 9.0) return 'destructive';
  if (score >= 7.0) return 'destructive'; // No orange by default, use destructive for High
  if (score >= 4.0) return 'secondary';
  return 'outline';
};

const getConfidenceBadgeVariant = (score: number): BadgeProps['variant'] => {
  if (score >= 0.8) return 'default';
  if (score >= 0.5) return 'secondary';
  return 'destructive';
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
  const { overallSummary, firmwareIdentification, bootlogAnalysis, cves, secrets, unsafeApis, sbom, fileSystemInsights, remediationPlan, potentialVulnerabilities } = analysis;

  const totalIssues = cves.length + secrets.length + unsafeApis.length + potentialVulnerabilities.length;
  
  const cveSeverityData = React.useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    cves.forEach((cve) => {
      if (cve.cvssScore >= 9.0) counts.Critical++;
      else if (cve.cvssScore >= 7.0) counts.High++;
      else if (cve.cvssScore >= 4.0) counts.Medium++;
      else counts.Low++;
    });
    return [
      { name: "Critical", value: counts.Critical, fill: "hsl(var(--destructive))" },
      { name: "High", value: counts.High, fill: "hsl(var(--chart-1))" },
      { name: "Medium", value: counts.Medium, fill: "hsl(var(--chart-5))" },
      { name: "Low", value: counts.Low, fill: "hsl(var(--chart-2))" },
    ].filter((d) => d.value > 0);
  }, [cves]);

  const issueBreakdownData = React.useMemo(() => {
    return [
      { name: "CVEs", value: cves.length, fill: "hsl(var(--chart-1))" },
      { name: "Secrets", value: secrets.length, fill: "hsl(var(--chart-2))" },
      { name: "Unsafe APIs", value: unsafeApis.length, fill: "hsl(var(--chart-3))" },
      { name: "Potential Vulns", value: potentialVulnerabilities.length, fill: "hsl(var(--chart-4))" },
    ].filter((d) => d.value > 0);
  }, [cves.length, secrets.length, unsafeApis.length, potentialVulnerabilities.length]);
  
  const handleExportJson = () => {
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
      JSON.stringify(analysis, null, 2)
    )}`;
    const link = document.createElement("a");
    link.href = jsonString;
    link.download = "firmware-analysis-report.json";
    link.click();
  };

  const deviceName = [firmwareIdentification.vendor, firmwareIdentification.model].filter(Boolean).join(' ') || "Unknown Device";

  return (
    <div className="w-full space-y-6 animate-in fade-in-50">
      <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground font-headline">Analysis Report</h1>
            <p className="text-muted-foreground">A summary of the security posture of your firmware.</p>
        </div>
        <div className="flex items-center gap-2">
            <Button onClick={handleExportJson} variant="outline">
              <Download className="mr-2 h-4 w-4" />
              Export JSON
            </Button>
            <Button onClick={onReset} variant="outline">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Analyze New Files
            </Button>
        </div>
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
                    Across all security categories
                </p>
            </CardContent>
        </Card>
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Identified Device</CardTitle>
                <DeviceTypeIcon type={firmwareIdentification.deviceType} />
            </CardHeader>
            <CardContent>
                <div className="text-2xl font-bold">{deviceName}</div>
                <div className="text-xs text-muted-foreground flex items-center gap-2">
                    <span>Confidence:</span>
                    <Badge variant={getConfidenceBadgeVariant(firmwareIdentification.confidence)}>
                      {(firmwareIdentification.confidence * 100).toFixed(0)}%
                    </Badge>
                </div>
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
          {firmwareIdentification.reasoning && (
             <p className="text-sm text-muted-foreground mt-2 pt-2 border-t border-border/50">
                <span className="font-semibold text-foreground">Identification Rationale:</span> {firmwareIdentification.reasoning}
              </p>
            )}
        </CardContent>
      </Card>
      
      {remediationPlan && remediationPlan.length > 0 && (
        <Card className="border-primary/50">
          <CardHeader className="flex flex-row items-center gap-3 space-y-0">
            <ShieldAlert className="h-6 w-6 text-primary" />
            <div>
              <CardTitle>Actionable Remediation Plan</CardTitle>
              <CardDescription>A prioritized list of steps to improve security.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <ol className="space-y-3 list-decimal list-inside">
              {remediationPlan.map((step) => (
                <li key={step.priority} className="text-muted-foreground">
                  <span className="font-semibold text-foreground">{step.description}</span>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>CVE Severity Distribution</CardTitle>
            <CardDescription>Breakdown of vulnerabilities by CVSS score.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-center">
            {cveSeverityData.length > 0 ? (
              <ChartContainer config={{}} className="mx-auto aspect-square h-[250px]">
                <PieChart>
                  <Tooltip
                    cursor={false}
                    content={<ChartTooltipContent hideLabel />}
                  />
                  <Pie
                    data={cveSeverityData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={60}
                    strokeWidth={5}
                  >
                    {cveSeverityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Legend content={<ChartLegendContent />} />
                </PieChart>
              </ChartContainer>
            ) : (
              <div className="flex items-center justify-center h-[250px] text-muted-foreground">
                No CVE data to display
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Issue Type Breakdown</CardTitle>
            <CardDescription>Distribution of all identified security issues.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-center">
            {issueBreakdownData.length > 0 ? (
              <ChartContainer config={{}} className="mx-auto aspect-square h-[250px]">
                <PieChart>
                  <Tooltip
                    cursor={false}
                    content={<ChartTooltipContent hideLabel />}
                  />
                  <Pie
                    data={issueBreakdownData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={60}
                    strokeWidth={5}
                  >
                    {issueBreakdownData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Legend content={<ChartLegendContent />} />
                </PieChart>
              </ChartContainer>
            ) : (
              <div className="flex items-center justify-center h-[250px] text-muted-foreground">
                 No issue data to display
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Accordion type="multiple" defaultValue={['potential-vulns', 'cves', 'secrets']} className="w-full space-y-4">
        
        {potentialVulnerabilities && potentialVulnerabilities.length > 0 && (
            <Card>
                <AccordionItem value="potential-vulns" className="border-b-0 border-destructive/50">
                    <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                        <div className="flex items-center gap-3">
                            <ShieldAlert className="h-6 w-6 text-destructive" />
                            <span>Potential Novel Vulnerabilities</span>
                            <Badge variant="destructive">{potentialVulnerabilities.length}</Badge>
                        </div>
                    </AccordionTrigger>
                    <AccordionContent className="px-6 pb-6">
                        <div className="space-y-4">
                            {potentialVulnerabilities.map((vuln, i) => (
                                <Card key={i} className="bg-muted/30">
                                    <CardHeader>
                                        <CardTitle className="text-base">{vuln.title}</CardTitle>
                                        {vuln.filePath && <CardDescription className="pt-1 font-mono text-xs">{vuln.filePath}</CardDescription>}
                                    </CardHeader>
                                    <CardContent>
                                        <h4 className="font-semibold mb-2 text-sm">Description:</h4>
                                        <p className="text-sm text-muted-foreground">{vuln.description}</p>
                                        <h4 className="font-semibold mt-4 mb-2 text-sm">Suggested Remediation:</h4>
                                        <p className="text-sm text-muted-foreground">{vuln.remediation}</p>
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    </AccordionContent>
                </AccordionItem>
            </Card>
        )}

        <Card>
          <AccordionItem value="cves" className="border-b-0">
            <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                <div className="flex items-center gap-3">
                    <AlertCircle className="h-6 w-6 text-primary" />
                    <span>CVEs Found</span>
                    <Badge variant="default">{cves.length}</Badge>
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
                                {cve.componentName && (
                                    <div className="mb-4">
                                        <h4 className="font-semibold mb-1 text-sm">Affected Component:</h4>
                                        <p className="text-sm text-muted-foreground font-mono">{cve.componentName} ({cve.componentVersion || 'version not specified'})</p>
                                    </div>
                                )}
                                <h4 className="font-semibold mb-2 text-sm">Summary:</h4>
                                <div className="pl-4 border-l-2 border-primary/50 space-y-1">
                                {(cve.summary || '').split('\n').map((line, i) => (
                                    line.trim() && <p key={i} className="text-sm text-muted-foreground">{line.replace(/^- /, '• ')}</p>
                                ))}
                                </div>
                                {cve.remediation && (
                                  <>
                                    <h4 className="font-semibold mt-4 mb-2 text-sm">Remediation:</h4>
                                    <p className="text-sm text-muted-foreground">{cve.remediation}</p>
                                  </>
                                )}
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
          <AccordionItem value="file-explorer" className="border-b-0">
            <AccordionTrigger className="px-6 py-4 text-lg font-medium">
                <div className="flex items-center gap-3">
                    <FolderTree className="h-6 w-6 text-[hsl(var(--chart-3))]" />
                    <span>File System & Malware Insights</span>
                    <Badge variant="secondary">{fileSystemInsights.length}</Badge>
                </div>
            </AccordionTrigger>
            <AccordionContent className="px-6 pb-6">
                 <div className="space-y-4">
                    {fileSystemInsights && fileSystemInsights.length > 0 ? fileSystemInsights.map((file, i) => (
                        <Card key={i} className="bg-muted/30">
                            <CardHeader>
                                <CardTitle className="flex items-center justify-between gap-2 text-base font-mono">
                                    <div className="flex items-center gap-2">
                                        <FileCode className="h-4 w-4 shrink-0" />
                                        <span className="truncate">{file.path}</span>
                                    </div>
                                    {file.threatType && <Badge variant="destructive">{file.threatType}</Badge>}
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                                <p className="text-sm text-muted-foreground">{file.description}</p>
                                {file.threatReasoning && (
                                    <div className="mt-2 pt-2 border-t border-border/50">
                                        <p className="text-sm text-destructive"><span className="font-semibold">Threat Rationale:</span> {file.threatReasoning}</p>
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    )) : <p className="text-muted-foreground">No specific file paths of interest were identified from the provided strings.</p>}
                </div>
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
