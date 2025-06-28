"use client";

import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { FileUploader } from '@/components/file-uploader';
import { AnalysisReport } from '@/components/analysis-report';
import type { AnalyzeFirmwareOutput } from '@/ai/flows/analyze-firmware';

export default function Home() {
  const [analysisResult, setAnalysisResult] = useState<AnalyzeFirmwareOutput | null>(null);

  if (analysisResult) {
    return (
      <div className="flex flex-col items-center justify-start min-h-screen bg-background text-foreground font-body p-4 sm:p-8">
        <div className="w-full max-w-5xl">
          <AnalysisReport 
            analysis={analysisResult} 
            onReset={() => setAnalysisResult(null)} 
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground font-body">
      <div className="container mx-auto px-4 py-8 sm:py-12 md:py-16">
        <div className="max-w-3xl mx-auto text-center">
            <header className="mb-8 sm:mb-12">
                <div className="inline-flex items-center justify-center bg-primary/10 p-3 rounded-full mb-4">
                    <ShieldCheck className="h-10 w-10 text-primary" />
                </div>
                <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-foreground font-headline">
                    Firmware Insights
                </h1>
                <p className="mt-4 text-lg text-muted-foreground max-w-2xl mx-auto">
                    Upload your firmware and bootlog files to uncover security vulnerabilities and gain deep insights.
                </p>
            </header>

            <main>
                <FileUploader onAnalysisComplete={setAnalysisResult} />
            </main>

            <footer className="mt-12 text-sm text-muted-foreground">
                <p>&copy; {new Date().getFullYear()} Firmware Insights. All Rights Reserved.</p>
            </footer>
        </div>
      </div>
    </div>
  );
}
