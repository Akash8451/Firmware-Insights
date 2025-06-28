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
  firmwareContent: z.string().describe('The extracted text strings from the .bin firmware file.'),
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
    cvssScore: z.number().describe('The CVSS v3 score, from 0.0 to 10.0.'),
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
    confidence: z.number().min(0).max(1).describe('The confidence score for the classification, from 0.0 to 1.0.'),
    reasoning: z.string().describe('Brief reasoning for the classification based on found files or strings.'),
});

const FileSystemInsightSchema = z.object({
    path: z.string().describe('The full file path identified, e.g., "/etc/shadow".'),
    description: z.string().describe('A brief explanation of why this file is noteworthy for security analysis.'),
    threatType: z.string().optional().describe('The type of threat detected, e.g., "Malware", "Suspicious Pattern", "Misconfiguration", "High-Risk Keyword".'),
    threatReasoning: z.string().optional().describe("An explanation of why this is considered a potential threat."),
});

const RemediationStepSchema = z.object({
    priority: z.number().describe("The priority of the remediation step, with 1 being the highest."),
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
  prompt: `You are an expert firmware security analysis tool. Your main task is to analyze the provided firmware strings and bootlog content to identify a wide range of security risks.

Your response MUST be a valid JSON object that strictly adheres to the provided output schema.

**Analysis Instructions:**

Based *only* on the provided \`firmwareContent\` and \`bootlogContent\`, perform the following analysis:

1.  **Overall Summary**: Write a concise, high-level summary of the firmware's security posture.
2.  **Firmware Type**: Classify the device type (e.g., "Router", "Camera", "IoT Sensor"). Provide a confidence score (0.0 to 1.0) and briefly explain your reasoning.
3.  **Bootlog Analysis**: From the bootlog, extract the Linux kernel version, any identified hardware, and loaded kernel modules. Summarize any interesting findings.
4.  **SBOM & CVEs**: Identify software components and their versions to create a simple Software Bill of Materials (SBOM). Based on the SBOM, list any associated Common Vulnerabilities and Exposures (CVEs). For each CVE, include its ID, a detailed description, its CVSSv3 score, a 2-3 bullet point summary of the risk, and a brief, actionable remediation step if possible.
5.  **Secrets**: Diligently scan for any hardcoded secrets. This includes API keys, private keys, tokens, and especially username/password pairs which might appear in various formats (e.g., \`user:pass\`, \`USER="admin" PASS="1234"\`). For each secret, note its type, value, and a remediation recommendation.
6.  **Unsafe APIs**: Identify the use of insecure C functions (like \`strcpy\`, \`gets\`) or weak cryptographic algorithms (like MD5, RC4). For each, provide the function/algorithm name and explain why it's a risk.
7.  **File System & Malware Insights**: Identify noteworthy file paths (e.g., \`/etc/shadow\`, \`/bin/sh\`). Pay special attention to keywords like \`upnp\`, \`ssh\`, \`root\`, \`shell\` and explain their security implications. If you suspect a file or pattern indicates malware or a backdoor, set the \`threatType\` and explain your reasoning.
8.  **Potential Novel Vulnerabilities (Zero-Day Analysis)**: Act as a reverse engineer. Go beyond known CVEs to find potential new vulnerabilities by analyzing how components, scripts, and configurations interact. For each potential vulnerability, provide a title, a detailed description of the logical flaw and its impact, and a suggested remediation.
9.  **Remediation Plan**: Create a prioritized, step-by-step remediation plan based on all your findings. Rank the steps from most to least critical.

**IMPORTANT**: If you cannot find any items for a particular array field (e.g., no CVEs are found), you MUST return an empty array \`[]\` for that field. Do not omit the field from the JSON output. Do not make up information that cannot be inferred from the provided text.

**Firmware Data:**

Bootlog contents:
{{{bootlogContent}}}

Extracted strings from firmware file:
{{{firmwareContent}}}
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
