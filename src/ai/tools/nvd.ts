'use server';

import {ai} from '@/ai/genkit';
import {z} from 'zod';
import {config} from 'dotenv';
import { CveSchema } from '../flows/analyze-firmware';

config(); // Load .env file

const NvdCveLookupSchema = z.object({
    componentName: z.string().describe('The name of the software component or package.'),
    componentVersion: z.string().describe('The version of the component.'),
});

// A simplified schema for the NVD CVE response
const NvdCveDetailSchema = z.object({
    id: z.string(),
    descriptions: z.array(z.object({lang: z.string(), value: z.string()})),
    metrics: z.object({
        cvssMetricV31: z.array(z.object({
            cvssData: z.object({
                baseScore: z.coerce.number(),
            }),
        })).optional(),
    }),
});

const NvdApiResponseSchema = z.object({
    vulnerabilities: z.array(z.object({ cve: NvdCveDetailSchema })),
});


export const getNvdCvesForComponent = ai.defineTool(
  {
    name: 'getNvdCvesForComponent',
    description: 'Looks up CVEs for a given software component and version from the National Vulnerability Database (NVD).',
    inputSchema: NvdCveLookupSchema,
    outputSchema: z.array(CveSchema),
  },
  async ({componentName, componentVersion}) => {
      const apiKey = process.env.NVD_API_KEY;
      if (!apiKey) {
          console.warn("NVD_API_KEY is not set. Using rate-limited access. See https://nvd.nist.gov/developers/request-an-api-key");
      }

      const searchString = `${componentName} ${componentVersion}`;
      // Use keywordExactMatch to improve accuracy
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(searchString)}&keywordExactMatch`;

      try {
          const response = await fetch(url, {
              headers: apiKey ? { apiKey } : {},
          });

          if (!response.ok) {
              const errorText = await response.text();
              // Don't throw for 404, it just means no results
              if (response.status === 404) return [];
              throw new Error(`NVD API request failed with status ${response.status}: ${errorText}`);
          }

          const data = await NvdApiResponseSchema.parseAsync(await response.json());

          return data.vulnerabilities.map(vuln => {
              const cve = vuln.cve;
              const description = cve.descriptions.find(d => d.lang === 'en')?.value || 'No description available.';
              const cvssScore = cve.metrics.cvssMetricV31?.[0]?.cvssData.baseScore || 0.0;
              
              // Return a structure that matches CveSchema, with empty fields for the AI to fill.
              return {
                  cveId: cve.id,
                  componentName: componentName,
                  componentVersion: componentVersion,
                  description: description,
                  cvssScore: cvssScore,
                  summary: '', // To be filled in by the AI later
                  remediation: '', // To be filled in by the AI later
              };
          });
      } catch (error) {
          console.error(`Error fetching CVEs for ${componentName} ${componentVersion}:`, error);
          return []; // Return empty array on error to not break the flow
      }
  }
);
