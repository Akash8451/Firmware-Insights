import {z} from 'zod';

export const CveSchema = z.object({
    cveId: z.string().describe('The CVE identifier, e.g., "CVE-2022-12345".'),
    componentName: z.string().describe('The name of the affected software component from the SBOM.'),
    componentVersion: z.string().describe('The version of the affected software component found in the firmware.'),
    description: z.string().describe('A detailed description of the vulnerability.'),
    cvssScore: z.coerce.number().describe('The CVSS v3 score, from 0.0 to 10.0.'),
    summary: z.string().describe('A 2-3 bullet point summary of the risk, formatted as a single string with newlines.'),
    remediation: z.string().optional().describe('A brief, actionable remediation step, e.g., "Upgrade package X to version Y".'),
});
