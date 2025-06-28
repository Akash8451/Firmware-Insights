"use client";

import React, { useState, useRef, useCallback } from "react";
import { UploadCloud, FileText, Binary, X, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { analyzeFirmware, type AnalyzeFirmwareOutput } from "@/ai/flows/analyze-firmware";
import { useToast } from "@/hooks/use-toast";


type UploadedFile = {
  id: string;
  file: File;
};

const acceptedFileTypes = [".bin", ".txt"];

function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

const fileToText = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsText(file);
  });
}

const fileToArrayBuffer = (file: File): Promise<ArrayBuffer> => {
  return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
  });
}

const extractStrings = (buffer: ArrayBuffer, minLength = 4, maxLength = 100000): string => {
  const view = new Uint8Array(buffer);
  let result = '';
  let currentString = '';
  for (let i = 0; i < view.length; i++) {
      if (result.length >= maxLength) {
        break;
      }
      const charCode = view[i];
      // Printable ASCII characters (32-126) plus newline, tab, and carriage return
      if ((charCode >= 32 && charCode <= 126) || charCode === 10 || charCode === 9 || charCode === 13) {
          currentString += String.fromCharCode(charCode);
      } else {
          if (currentString.length >= minLength) {
              result += currentString + '\n';
          }
          currentString = '';
      }
  }
  if (currentString.length >= minLength && result.length < maxLength) {
      result += currentString;
  }
  return result.substring(0, maxLength);
}


export function FileUploader({ onAnalysisComplete }: { onAnalysisComplete: (result: AnalyzeFirmwareOutput) => void }) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const handleFileChange = (newFiles: FileList | null) => {
    if (newFiles) {
      const filteredFiles = Array.from(newFiles).filter(file =>
        acceptedFileTypes.some(type => file.name.endsWith(type))
      );

      const newUploadedFiles: UploadedFile[] = filteredFiles.map(file => ({
        id: crypto.randomUUID(),
        file,
      }));

      setFiles(prev => [...prev, ...newUploadedFiles]);
    }
  };

  const onDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const onDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    handleFileChange(e.dataTransfer.files);
  }, []);

  const onFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    handleFileChange(e.target.files);
  };

  const removeFile = (id: string) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  };
  
  const handleAnalyze = async () => {
    if (files.length === 0) return;
    setIsAnalyzing(true);

    const binFile = files.find(f => f.file.name.endsWith('.bin'))?.file;
    const txtFile = files.find(f => f.file.name.endsWith('.txt'))?.file;
    
    if (!binFile && !txtFile) {
        toast({
            title: "No valid files found",
            description: "Please upload at least one .bin or .txt file.",
            variant: "destructive",
        });
        setIsAnalyzing(false);
        return;
    }

    try {
        let firmwareContent: string | undefined;
        if (binFile) {
            const arrayBuffer = await fileToArrayBuffer(binFile);
            firmwareContent = extractStrings(arrayBuffer);
        }
        
        const bootlogContent = txtFile ? await fileToText(txtFile) : undefined;
        
        const result = await analyzeFirmware({ firmwareContent, bootlogContent });
        onAnalysisComplete(result);
    } catch (error) {
        console.error("Analysis failed:", error);
        const errorMessage = error instanceof Error ? error.message : "An unknown error occurred.";
        toast({
            title: "Analysis Failed",
            description: `Something went wrong during the analysis: ${errorMessage}`,
            variant: "destructive",
        });
    } finally {
        setIsAnalyzing(false);
    }
  };

  const FileIcon = ({ file }: { file: File }) => {
    if (file.name.endsWith('.bin')) {
      return <Binary className="h-6 w-6 text-primary" />;
    }
    if (file.name.endsWith('.txt')) {
      return <FileText className="h-6 w-6 text-primary" />;
    }
    return <FileText className="h-6 w-6 text-muted-foreground" />;
  };

  return (
    <Card className="w-full shadow-lg">
      <CardHeader>
        <CardTitle>Upload Firmware Files</CardTitle>
        <CardDescription>Drag and drop your .bin and bootlog.txt files or click to browse.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div
          className={cn(
            "flex flex-col items-center justify-center w-full p-12 border-2 border-dashed rounded-lg cursor-pointer transition-colors",
            isDragging ? "border-primary bg-primary/10" : "border-border hover:border-primary/50"
          )}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <UploadCloud className="w-12 h-12 text-muted-foreground" />
          <p className="mt-4 text-center text-muted-foreground">
            <span className="font-semibold text-primary">Click to upload</span> or drag and drop
          </p>
          <p className="text-xs text-muted-foreground">.bin and .txt files supported</p>
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            multiple
            onChange={onFileSelect}
            accept=".bin,.txt"
          />
        </div>

        {files.length > 0 && (
          <div className="space-y-4">
            <h3 className="font-medium text-foreground">Uploaded Files:</h3>
            <ul className="space-y-3">
              {files.map(uploadedFile => (
                <li key={uploadedFile.id} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-4 min-w-0">
                    <FileIcon file={uploadedFile.file} />
                    <div className="flex flex-col min-w-0">
                      <span className="text-sm font-medium text-foreground truncate">{uploadedFile.file.name}</span>
                      <span className="text-xs text-muted-foreground">{formatBytes(uploadedFile.file.size)}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Badge variant={uploadedFile.file.name.endsWith('.bin') ? 'default' : 'secondary'} className="hidden sm:inline-flex">
                      {uploadedFile.file.name.split('.').pop()}
                    </Badge>
                    <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => removeFile(uploadedFile.id)} disabled={isAnalyzing}>
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
        
        {files.length > 0 && (
          <div className="space-y-4 pt-4">
            <Button
              onClick={handleAnalyze}
              disabled={files.length === 0 || isAnalyzing}
              className="w-full bg-accent hover:bg-accent/90 text-accent-foreground"
              size="lg"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Analyzing...
                </>
              ) : "Analyze Files"}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
