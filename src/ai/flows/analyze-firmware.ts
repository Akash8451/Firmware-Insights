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
  firmwareContent: z.string().optional().describe('The extracted strings from the .bin firmware file.'),
  bootlogContent: z.string().optional().describe('The content of the bootlog.txt file.'),
});
export type AnalyzeFirmwareInput = z.infer<typeof AnalyzeFirmwareInputSchema>;

const SecretSchema = z.object({
    type: z.string().describe('Type of secret, e.g., "API Key", "Password", "Private Key".'),
    value: z.string().describe('The detected secret string.'),
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
});

const RemediationStepSchema = z.object({
    priority: z.number().describe("The priority of the remediation step, with 1 being the highest."),
    description: z.string().describe("A detailed description of the remediation action to be taken."),
});

const AnalyzeFirmwareOutputSchema = z.object({
    overallSummary: z.string().describe("A high-level summary of the firmware's security posture in a single paragraph."),
    firmwareType: FirmwareTypeSchema,
    bootlogAnalysis: BootlogAnalysisSchema,
    cves: z.array(CveSchema).describe('A list of Common Vulnerabilities and Exposures (CVEs) found.'),
    secrets: z.array(SecretSchema).describe('A list of hardcoded secrets found.'),
    unsafeApis: z.array(UnsafeApiSchema).describe('A list of unsafe API calls or weak crypto algorithms found.'),
    sbom: z.array(SbomComponentSchema).describe('A list of software components identified in the firmware (Software Bill of Materials).'),
    fileSystemInsights: z.array(FileSystemInsightSchema).describe('A list of noteworthy files and paths found within the firmware strings.'),
    remediationPlan: z.array(RemediationStepSchema).describe("A prioritized list of actionable remediation steps, ranked from most to least critical."),
});
export type AnalyzeFirmwareOutput = z.infer<typeof AnalyzeFirmwareOutputSchema>;


export async function analyzeFirmware(input: AnalyzeFirmwareInput): Promise<AnalyzeFirmwareOutput> {
  return analyzeFirmwareFlow(input);
}

const prompt = ai.definePrompt({
  name: 'analyzeFirmwarePrompt',
  input: {schema: AnalyzeFirmwareInputSchema},
  output: {schema: AnalyzeFirmwareOutputSchema},
  prompt: `You are a world-class firmware security analyst and remediation expert. Your task is to analyze the provided firmware content and bootlog to identify security vulnerabilities, hardcoded secrets, unsafe API usage, and other potential risks, and then create a prioritized action plan.

You must provide your analysis in a structured JSON format.

Here is the data you need to analyze:

Bootlog contents:
{{{bootlogContent}}}

Extracted strings from firmware file:
{{{firmwareContent}}}

Please perform the following analysis based ONLY on the provided content:
1.  **Bootlog Analysis**: Parse the bootlog to identify the kernel version, any hardware identifiers, detected kernel modules with their versions (e.g., "ath9k 1.0.0"), and summarize any anomalies or interesting entries in plain English.
2.  **Secrets Detection**: Perform a comprehensive scan for hardcoded secrets. For each potential secret found, describe its likely type, report the detected value, and provide a clear recommendation for remediation. Be diligent, as secrets can be disguised.
3.  **Unsafe API Usage**: Scan the extracted firmware strings for usage of known insecure C functions (like strcpy, gets, sprintf) or weak cryptographic algorithms (MD5, RC4).
4.  **CVE Lookup (Simulated)**: Based on identified components, list potential CVEs. For each CVE, provide its ID, a detailed description, a CVSS score (0.0-10.0), a 2-3 bullet point summary of the risk, and a brief, actionable remediation step (e.g., "Upgrade 'openssl' to version '1.1.1k' or later.").
5.  **SBOM Generation**: Identify software packages, libraries, and applications to generate a Software Bill of Materials (SBOM).
6.  **Firmware Type Classification**: Heuristically determine the device type, confidence score, and justification.
7.  **File System Insights**: Identify noteworthy file paths relevant to security analysis and explain their significance.
8.  **Overall Summary**: Provide a high-level summary of the firmware's security posture in a single paragraph.
9.  **Automated Remediation Plan**: Based on ALL findings, generate a prioritized, step-by-step remediation plan. Rank actions from most to least critical. Each step should be a clear, actionable instruction. For example: "1. Critical: Rotate the leaked AWS API key found in '/etc/config.json'.", "2. High: Patch CVE-2022-12345 by upgrading the 'openssl' package to version '1.1.1k'.", "3. Medium: Replace the use of 'strcpy' in the '/bin/login' binary with 'strncpy' to prevent buffer overflows."

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
