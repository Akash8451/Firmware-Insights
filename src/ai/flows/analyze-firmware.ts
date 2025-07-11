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
import { CveSchema } from '@/ai/schemas';
import { getNvdCvesForComponent } from '@/ai/tools/nvd';

const AnalyzeFirmwareInputSchema = z.object({
  firmwareContent: z.string().optional().describe('The extracted text strings from the .bin firmware file.'),
  bootlogContent: z.string().optional().describe('The content of the bootlog.txt file.'),
});
export type AnalyzeFirmwareInput = z.infer<typeof AnalyzeFirmwareInputSchema>;

const SecretSchema = z.object({
    type: z.string().describe('Type of secret, e.g., "API Key", "Password", "Username/Password Pair", "Private Key", "X.509 Certificate".'),
    value: z.string().describe('The detected secret string or username/password pair.'),
    recommendation: z.string().describe('Recommendation for remediation, e.g., "Rotate key and store in a secure vault."'),
});

const UnsafeApiSchema = z.object({
    functionName: z.string().describe('The name of the unsafe function or algorithm, e.g., "strcpy", "MD5".'),
    reason: z.string().describe('A brief explanation of why it is unsafe.'),
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

const SbomComponentAnalysisSchema = SbomComponentSchema.extend({
    cves: z.array(CveSchema).describe("A list of CVEs associated with this component. The 'description' field contains the raw data from the NVD API, while 'summary' and 'remediation' are AI-enhanced."),
});

const FirmwareIdentificationSchema = z.object({
    vendor: z.string().optional().describe('The identified vendor, e.g., "TP-Link".'),
    model: z.string().optional().describe('The identified device model, e.g., "TL-WR845N".'),
    version: z.string().optional().describe('The identified firmware version, e.g., "V4_190219".'),
    deviceType: z.string().describe('The classified device type, e.g., "Router", "Camera", "IoT Sensor", "Unknown".'),
    confidence: z.coerce.number().min(0).max(1).describe('The overall confidence score (from 0.0 to 1.0) for this identification, based on the quality and quantity of evidence.'),
    reasoning: z.string().describe('Detailed reasoning for the identification, referencing specific evidence like file paths (e.g., "/etc/version"), strings found, or patterns matched.'),
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

const OrganizedContentSchema = z.object({
    filePath: z.string().describe("The inferred file path, e.g., '/etc/config/system' or 'Inferred Shell Script' if no path is clear."),
    contentType: z.string().describe("The type of content, e.g., 'Configuration', 'HTML', 'JavaScript', 'Shell Script', 'Certificate', 'Log'."),
    summary: z.string().describe("A one-sentence summary of the content's purpose and significance."),
    content: z.string().describe("The reconstructed block of text from the raw strings that represents this file's content."),
});


const AnalyzeFirmwareOutputSchema = z.object({
    overallSummary: z.string().describe("A high-level summary of the firmware's security posture in a single paragraph."),
    firmwareIdentification: FirmwareIdentificationSchema,
    bootlogAnalysis: BootlogAnalysisSchema,
    secrets: z.array(SecretSchema).describe('A list of hardcoded secrets found, including username/password pairs.'),
    unsafeApis: z.array(UnsafeApiSchema).describe('A list of unsafe API calls or weak crypto algorithms found.'),
    sbomAnalysis: z.array(SbomComponentAnalysisSchema).describe("An analysis of each component from the Software Bill of Materials, including any associated CVEs."),
    fileSystemInsights: z.array(FileSystemInsightSchema).describe('A list of noteworthy files and paths found within the firmware strings, including potential malware.'),
    organizedContents: z.array(OrganizedContentSchema).describe("Key file contents, scripts, and logs extracted and categorized from the raw firmware strings and bootlog."),
    remediationPlan: z.array(RemediationStepSchema).describe("A prioritized list of actionable remediation steps, ranked from most to least critical."),
    potentialVulnerabilities: z.array(PotentialVulnerabilitySchema).describe("A list of potential zero-day or novel vulnerabilities discovered through deep analysis."),
});
export type AnalyzeFirmwareOutput = z.infer<typeof AnalyzeFirmwareOutputSchema>;


export async function analyzeFirmware(input: AnalyzeFirmwareInput): Promise<AnalyzeFirmwareOutput> {
  return analyzeFirmwareFlow(input);
}


// Prompt 1: Initial analysis to get SBOM and device identity
const identifyAndSbomPrompt = ai.definePrompt({
    name: 'identifyAndSbomPrompt',
    input: { schema: AnalyzeFirmwareInputSchema },
    output: { schema: z.object({
        firmwareIdentification: FirmwareIdentificationSchema,
        bootlogAnalysis: BootlogAnalysisSchema,
        sbom: z.array(SbomComponentSchema),
    })},
    prompt: `You are an expert firmware security analysis tool. Your task is to perform an initial analysis on the provided firmware strings and bootlog content.
    
    Based *only* on the provided \`firmwareContent\` and \`bootlogContent\`, perform the following analysis:

    1.  **Firmware Identification (Heuristic Analysis)**: Do not assume standard file paths exist. Instead, act as if you are running \`grep\` with flexible patterns across all provided text.
        *   **Search Heuristics**: Look for keywords like "model", "version", "board", "firmware" and vendor names (e.g., "TP-LINK", "NETGEAR", "D-Link"). Search for version patterns like \`V[0-9]\`. Check for embedded metadata in HTML \`<title>\` tags or JavaScript variables within \`/web/\` or \`/www/\` paths.
        *   **Synthesize & Score**: Based on all evidence found, identify the \`vendor\`, \`model\`, \`version\`, and \`deviceType\`.
        *   **Confidence Score**: Assign a \`confidence\` score from 0.0 (total guess) to 1.0 (explicitly stated in a reliable file). A high score requires strong evidence (e.g., model found in \`/etc/product_info\`). A low score would be for a model inferred from a few strings in a generic binary.
        *   **Reasoning**: Provide detailed \`reasoning\`, citing the source of each piece of evidence (e.g., "Vendor 'TP-Link' found in /web/login.html. Model 'TL-WR845N' found in string near 'board_name'.").

    2.  **Bootlog Analysis**: From the bootlog, extract the Linux kernel version, any identified hardware, and loaded kernel modules. Summarize any interesting findings.
    
    3.  **SBOM Generation**: Scour the entire \`firmwareContent\` for any mention of software components and their versions (e.g., "BusyBox 1.25.1", "OpenSSL 1.1.1k"). Pay close attention to common firmware components like BusyBox, U-Boot, OpenSSL, dropbear, dnsmasq, etc. Create a comprehensive Software Bill of Materials (SBOM) from these findings. Each entry must have a name, version, and type. If you identify a component but cannot find a version, do not include it.

    Your response MUST be a valid JSON object that strictly adheres to the provided output schema. If a section is empty, return an empty array or object as appropriate.
    
    **Firmware Data:**

    Bootlog contents:
    {{{bootlogContent}}}

    Extracted strings from firmware file:
    {{{firmwareContent}}}
    `,
});

// Prompt 2: Enrichment and final analysis
const enrichmentPrompt = ai.definePrompt({
    name: 'enrichmentPrompt',
    input: { schema: z.object({
        firmwareContent: z.string().optional(),
        bootlogContent: z.string().optional(),
        firmwareIdentification: FirmwareIdentificationSchema,
        bootlogAnalysis: BootlogAnalysisSchema,
        sbomAnalysis: z.array(SbomComponentAnalysisSchema),
    })},
    output: { schema: AnalyzeFirmwareOutputSchema },
    prompt: `You are an expert firmware security analysis tool. You have been provided with an initial analysis of a firmware (device identity, bootlog info) and an SBOM analysis containing a list of components and their associated raw CVE data from the NVD API.

    Your main task is to **enrich this data and perform a deeper security analysis** to generate a final, comprehensive report.

    Your response MUST be a valid JSON object that strictly adheres to the provided output schema.

    **Analysis Instructions:**

    1.  **Overall Summary**: Based on all the provided information (initial analysis, CVEs, file content), write a concise, high-level summary of the firmware's security posture.

    2.  **Enrich CVE Data**: For each component in the \`sbomAnalysis\` array, and for each CVE within that component's \`cves\` array, generate a concise 2-3 bullet point \`summary\` of the risk and a brief, actionable \`remediation\` step. The other CVE fields (including the raw \`description\`) are already populated from the NVD API.

    3.  **Secrets**: Diligently scan the raw \`firmwareContent\` for any hardcoded secrets. This includes API keys, private keys (especially those enclosed in \`-----BEGIN...-----\` blocks), X.509 certificates, tokens, and especially username/password pairs which might appear in various formats (e.g., \`user:pass\`, \`USER="admin" PASS="1234"\`).

    4.  **Unsafe APIs**: Identify the use of insecure C functions (like \`strcpy\`, \`gets\`) or weak cryptographic algorithms (like MD5, RC4) from the raw \`firmwareContent\`.

    5.  **File System & Malware Insights**: Identify noteworthy file paths (e.g., \`/etc/shadow\`, \`/bin/sh\`). Pay special attention to keywords like \`upnp\`, \`ssh\`, \`root\`, \`shell\` and explain their security implications from the raw \`firmwareContent\`. If you suspect a file or pattern indicates malware or a backdoor (like Xiongmai XMeye), set the \`threatType\` to "Malware" or "Suspicious Pattern" and explain your reasoning in \`threatReasoning\`.

    6.  **Potential Novel Vulnerabilities (Zero-Day Analysis)**: Act as a reverse engineer. Go beyond known CVEs to find potential new vulnerabilities by analyzing how components, scripts, and configurations interact in the raw \`firmwareContent\`. Look for password hashes (strings starting with patterns like \`$1$\`, \`$5$\`, \`$6$\`), check for weak or default configurations in identified configuration files, or identify suspicious custom services or scripts that might be backdoors. For each finding, create a \`PotentialVulnerability\` entry.

    7.  **Organize Raw Data**: Reconstruct and categorize the most important text blocks from the raw \`firmwareContent\` and \`bootlogContent\`. For each block, determine a file path (if possible), its content type (like 'HTML', 'Shell Script', 'Config'), provide a summary, and include the reconstructed text content. Populate the \`organizedContents\` field with this data.

    8.  **Remediation Plan**: Create a prioritized, step-by-step remediation plan based on all your findings (enriched CVEs, secrets, unsafe APIs, potential vulns, etc.). Rank the steps from most to least critical.

    **IMPORTANT**: You MUST return the \`firmwareIdentification\`, and \`bootlogAnalysis\` fields from the input directly in your output. For the \`sbomAnalysis\` field, you must return the structure you were given, but with the AI-enhanced \`summary\` and \`remediation\` fields filled in for each CVE. If any array is empty, return \`[]\`.

    **Input Data:**

    **Initial Analysis:**
    Firmware Identification: {{{json firmwareIdentification}}}
    Bootlog Analysis: {{{json bootlogAnalysis}}}
    
    **SBOM with Raw CVEs from NVD API:**
    {{{json sbomAnalysis}}}

    **Raw Firmware Data:**
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
  async (input) => {
    // Step 1: Get initial analysis and SBOM from AI
    const { output: initialAnalysis } = await identifyAndSbomPrompt(input);
    if (!initialAnalysis) {
        throw new Error("Failed to get initial analysis from AI.");
    }
    
    // Step 2: Concurrently fetch CVEs for all SBOM components using the NVD tool
    const cvePromises = initialAnalysis.sbom.map(component => 
        getNvdCvesForComponent({
            componentName: component.name,
            componentVersion: component.version
        })
    );
    const cveResults = await Promise.all(cvePromises);
    const allCvesFromApi = cveResults.flat();

    // Step 3: Combine SBOM and CVEs into a single structure
    const sbomAnalysisWithRawCves = initialAnalysis.sbom.map(component => {
        const componentCves = allCvesFromApi.filter(
            cve => cve.componentName === component.name && cve.componentVersion === component.version
        );
        return {
            ...component,
            cves: componentCves,
        };
    });

    // Step 4: Call the enrichment prompt with all the data
    const { output: finalAnalysis } = await enrichmentPrompt({
        firmwareContent: input.firmwareContent,
        bootlogContent: input.bootlogContent,
        firmwareIdentification: initialAnalysis.firmwareIdentification,
        bootlogAnalysis: initialAnalysis.bootlogAnalysis,
        sbomAnalysis: sbomAnalysisWithRawCves,
    });
    
    if (!finalAnalysis) {
        throw new Error("Failed to get final analysis from AI.");
    }

    return finalAnalysis;
  }
);
