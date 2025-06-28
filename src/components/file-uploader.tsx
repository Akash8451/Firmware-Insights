"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { UploadCloud, FileText, Binary, X, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

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

export function FileUploader() {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
  
  const handleAnalyze = () => {
    if (files.length === 0) return;
    setIsAnalyzing(true);
    setProgress(0);
  };

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isAnalyzing) {
      timer = setInterval(() => {
        setProgress(prev => {
          if (prev >= 100) {
            clearInterval(timer);
            setTimeout(() => {
              setIsAnalyzing(false);
            }, 500);
            return 100;
          }
          return prev + 1;
        });
      }, 50);
    }
    return () => clearInterval(timer);
  }, [isAnalyzing]);
  
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
            {isAnalyzing && (
              <div className="space-y-2">
                  <div className="flex justify-between text-sm font-medium">
                      <span>Analyzing...</span>
                      <span>{Math.round(progress)}%</span>
                  </div>
                  <Progress value={progress} className="w-full" />
              </div>
            )}
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
