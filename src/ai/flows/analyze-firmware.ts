'use server';
/**
 * @fileOverview A firmware analysis AI agent.
 *
 * - analyzeFirmware - A function that handles the firmware analysis process.
 * - AnalyzeFirmwareInput - The input type for the analyzeFirmware function.
 * - AnalyzeFirmwareOutput - The return type for the analyzeFirmware function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'zod';

const AnalyzeFirmwareInputSchema = z.object({
  firmwareContent: z.string().optional().describe('The extracted text strings from the .bin firmware file.'),
  bootlogContent: z.string().optional().describe('The content of the bootlog.txt file.'),
});
export type AnalyzeFirmwareInput = z.infer<typeof AnalyzeFirmwareInputSchema>;

const SecretSchema = z.object({
    type: z.string().describe('Type of secret, e.g., "API Key", "Password", "Username/Password Pair", "Private Key".'),
    value: z.string().describe('The detected secret string or username/password pair.'),
    recommendation: z.string().describe('Recommendation for remediation, e.g., "Rotate key and store in a secure vault."'),
});

const UnsafeApiSchema = z.object({
    functionName: z.string().describe('The name of the unsafe function or algorithm, e.g., "strcpy", "MD5".'),
    reason: z.string().describe('A brief explanation of why it is unsafe.'),
});

const CveSchema = z.object({
    cveId: z.string().describe('The CVE identifier, e.g., "CVE-2022-12345".'),
    description: z.string().describe('A detailed description of the vulnerability.'),
    cvssScore: z.coerce.number().describe('The CVSS v3 score, from 0.0 to 10.0.'),
    summary: z.string().describe('A 2-3 bullet point summary of the risk, formatted as a single string with newlines.'),
    remediation: z.string().optional().describe('A brief, actionable remediation step, e.g., "Upgrade package X to version Y".'),
});

const BootlogAnalysisSchema = z.object({
    kernelVersion: z.string().optional().describe('The detected Linux kernel version.'),
    hardware: z.array(z.string()).describe('A list of identified hardware models or components.'),
    modules: z.array(z.string()).describe('A list of detected kernel modules or drivers and their versions, e.g., "ath9k 1.0.0".'),
    summary: z.string().describe('A summary of interesting findings or anomalies in the bootlog.'),
});

const SbomComponentSchema = z.object({
    name: z.string().describe('The name of the software component or package.'),
    version: z.string().describe('The version of the component.'),
    type: z.string().describe('The type of component, e.g., "OS Package", "Library", "Application".'),
});

const FirmwareTypeSchema = z.object({
    type: z.string().describe('The classified device type, e.g., "Router", "Camera", "IoT Sensor", "Unknown".'),
    confidence: z.coerce.number().min(0).max(1).describe('The confidence score for the classification, from 0.0 to 1.0.'),
    reasoning: z.string().describe('Brief reasoning for the classification based on found files or strings.'),
});

const FileSystemInsightSchema = z.object({
    path: z.string().describe('The full file path identified, e.g., "/etc/shadow".'),
    description: z.string().describe('A brief explanation of why this file is noteworthy for security analysis.'),
    threatType: z.string().optional().describe('The type of threat detected, e.g., "Malware", "Suspicious Pattern", "Misconfiguration", "High-Risk Keyword".'),
    threatReasoning: z.string().optional().describe("An explanation of why this is considered a potential threat."),
});

const RemediationStepSchema = z.object({
    priority: z.coerce.number().describe("The priority of the remediation step, with 1 being the highest."),
    description: z.string().describe("A detailed description of the remediation action to be taken."),
});

const PotentialVulnerabilitySchema = z.object({
    title: z.string().describe("A concise title for the potential vulnerability."),
    filePath: z.string().optional().describe("The file path or component where the issue is suspected."),
    description: z.string().describe("A detailed description of the suspected vulnerability and its potential impact."),
    remediation: z.string().describe("A suggested remediation or mitigation strategy."),
});


const AnalyzeFirmwareOutputSchema = z.object({
    overallSummary: z.string().describe("A high-level summary of the firmware's security posture in a single paragraph."),
    firmwareType: FirmwareTypeSchema,
    bootlogAnalysis: BootlogAnalysisSchema,
    cves: z.array(CveSchema).describe('A list of Common Vulnerabilities and Exposures (CVEs) found.'),
    secrets: z.array(SecretSchema).describe('A list of hardcoded secrets found, including username/password pairs.'),
    unsafeApis: z.array(UnsafeApiSchema).describe('A list of unsafe API calls or weak crypto algorithms found.'),
    sbom: z.array(SbomComponentSchema).describe('A list of software components identified in the firmware (Software Bill of Materials).'),
    fileSystemInsights: z.array(FileSystemInsightSchema).describe('A list of noteworthy files and paths found within the firmware strings, including potential malware.'),
    remediationPlan: z.array(RemediationStepSchema).describe("A prioritized list of actionable remediation steps, ranked from most to least critical."),
    potentialVulnerabilities: z.array(PotentialVulnerabilitySchema).describe("A list of potential zero-day or novel vulnerabilities discovered through deep analysis."),
});
export type AnalyzeFirmwareOutput = z.infer<typeof AnalyzeFirmwareOutputSchema>;


export async function analyzeFirmware(input: AnalyzeFirmwareInput): Promise<AnalyzeFirmwareOutput> {
  return analyzeFirmwareFlow(input);
}

const prompt = ai.definePrompt({
  name: 'analyzeFirmwarePrompt',
  input: {schema: AnalyzeFirmwareInputSchema},
  output: {schema: AnalyzeFirmwareOutputSchema},
  prompt: `You are a world-class firmware security analyst, reverse engineer, and remediation expert. Your task is to perform a deep analysis of the provided firmware content and bootlog to identify vulnerabilities, secrets, and other risks, and then create a prioritized action plan.

You must provide your analysis in a structured JSON format.

Here is the data you need to analyze:

Bootlog contents:
{{{bootlogContent}}}

Extracted strings from firmware file:
{{{firmwareContent}}}

Please perform the following analysis based ONLY on the provided content:
1.  **Deep Secret Detection**: Perform a comprehensive scan for hardcoded secrets. Pay special attention to username/password combinations, private keys, and API tokens. Be diligent, as secrets can be disguised.
2.  **File System and Malware Analysis**: Identify noteworthy file paths. Scrutinize the firmware strings for keywords like 'upnp', 'ssh', 'root', 'shell'. When found, create a File System Insight and explain the security implications. Scan for signs of malware or suspicious backdoors (e.g., unusual script names, obfuscated code, connections to suspicious domains). If found, tag it with a 'threatType' and provide 'threatReasoning'.
3.  **Bootlog Analysis**: Parse the bootlog to identify the kernel version, hardware identifiers, and detected kernel modules with versions.
4.  **Unsafe API Usage**: Scan for usage of insecure C functions (strcpy, gets) or weak crypto (MD5, RC4).
5.  **SBOM & CVE Lookup**: Generate an SBOM from identified components. Based on these, list potential CVEs with their ID, description, CVSS score, a 2-3 bullet point risk summary, and a brief remediation step.
6.  **Firmware Type Classification**: Heuristically determine the device type, confidence score, and justification.
7.  **Potential Vulnerability Discovery (Zero-Day Analysis)**: Go beyond known CVEs. Act as a reverse engineer. Analyze the interplay between components, scripts, and configurations to uncover *potential new vulnerabilities*. For each finding, describe the logical flaw, its potential impact, and a suggested remediation.
8.  **Overall Summary**: Provide a high-level summary of the firmware's security posture.
9.  **Automated Remediation Plan**: Based on ALL findings (CVEs, secrets, potential vulnerabilities), generate a prioritized, step-by-step remediation plan. Rank actions from most to least critical.

Your response must be a valid JSON object matching the requested schema. Do not make up information that cannot be inferred from the provided text.
`,
});

const analyzeFirmwareFlow = ai.defineFlow(
  {
    name: 'analyzeFirmwareFlow',
    inputSchema: AnalyzeFirmwareInputSchema,
    outputSchema: AnalyzeFirmwareOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    if (!output) {
      throw new Error("Failed to get analysis from AI.");
    }
    return output;
  }
);
