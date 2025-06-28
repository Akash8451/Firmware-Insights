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

const AnalyzeFirmwareOutputSchema = z.object({
    overallSummary: z.string().describe("A high-level summary of the firmware's security posture in a single paragraph."),
    bootlogAnalysis: BootlogAnalysisSchema,
    cves: z.array(CveSchema).describe('A list of Common Vulnerabilities and Exposures (CVEs) found.'),
    secrets: z.array(SecretSchema).describe('A list of hardcoded secrets found.'),
    unsafeApis: z.array(UnsafeApiSchema).describe('A list of unsafe API calls or weak crypto algorithms found.'),
    sbom: z.array(SbomComponentSchema).describe('A list of software components identified in the firmware (Software Bill of Materials).'),
});
export type AnalyzeFirmwareOutput = z.infer<typeof AnalyzeFirmwareOutputSchema>;


export async function analyzeFirmware(input: AnalyzeFirmwareInput): Promise<AnalyzeFirmwareOutput> {
  return analyzeFirmwareFlow(input);
}

const prompt = ai.definePrompt({
  name: 'analyzeFirmwarePrompt',
  input: {schema: AnalyzeFirmwareInputSchema},
  output: {schema: AnalyzeFirmwareOutputSchema},
  prompt: `You are a world-class firmware security analyst. Your task is to analyze the provided firmware content and bootlog to identify security vulnerabilities, hardcoded secrets, unsafe API usage, and other potential risks.

You must provide your analysis in a structured JSON format.

Here is the data you need to analyze:

Bootlog contents:
{{{bootlogContent}}}

Extracted strings from firmware file:
{{{firmwareContent}}}

Please perform the following analysis based ONLY on the provided content:
1.  **Bootlog Analysis**: Parse the bootlog to identify the kernel version, any hardware identifiers, detected kernel modules with their versions (e.g., "ath9k 1.0.0"), and summarize any anomalies or interesting entries.
2.  **Secrets Detection**: Scan the extracted firmware strings and bootlog for anything that looks like a hardcoded secret (API keys, passwords, private keys). For each, describe what it is and recommend rotating it.
3.  **Unsafe API Usage**: Scan the extracted firmware strings for usage of known insecure C functions (like strcpy, gets, sprintf) or weak cryptographic algorithms (MD5, RC4).
4.  **CVE Lookup (Simulated)**: Based on the identified kernel version and any other software components you can infer from the text, list potential CVEs. For each CVE, provide its ID, a brief description, a CVSS score (provide a realistic one between 0.0 and 10.0), and a 2-3 bullet point summary of the risk.
5.  **SBOM Generation**: From the firmware strings and bootlog, identify software packages, libraries, and applications (like dropbear, busybox, dnsmasq, etc.). For each, list its name, version, and type (e.g., "OS Package", "Library", "Application"). This should resemble a Software Bill of Materials (SBOM).
6.  **Overall Summary**: Provide a high-level summary of the firmware's security posture in a paragraph.

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
