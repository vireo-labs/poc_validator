"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type ValidationMode = "single" | "batch";

type SingleStatus = "PENDING" | "PARSING" | "ANALYZING" | "DISCOVERING" | "EXECUTING" | "JUDGING" | "COMPLETED" | "FAILED";
type BatchStatus = "pending" | "running" | "completed" | "failed";

interface SingleResult {
    id: number;
    status: SingleStatus;
    verdict: string | null;
    parsed_data?: Record<string, unknown>;
    code_analysis?: Record<string, unknown>;
    exploit_name?: string;
    execution_output?: {
        stdout: string;
        stderr: string;
        exit_code: number;
        duration_ms: number;
    };
    judge_reasoning?: string;
}

interface BatchResult {
    job_id: string;
    status: BatchStatus;
    total_alerts: number;
    unique_vulnerabilities: number;
    progress?: {
        current: number;
        total: number;
        current_package: string | null;
        completed: Array<{
            package: string;
            verdict: string;
            reason: string;
        }>;
    };
    summary?: {
        exploitable_count: number;
        by_verdict: Record<string, number>;
    };
    exploitable?: Array<{
        package: string;
        severity: string;
        title: string;
        exploit_source: string;
    }>;
    results?: Array<{
        package: string;
        verdict: string;
        reason: string;
    }>;
    error?: string;
}


const AGENTS = [
    { key: "PARSING", icon: "📄", name: "Report Parser", desc: "Extracting vulnerability details" },
    { key: "ANALYZING", icon: "🔍", name: "Code Analyzer", desc: "Cloning repo & searching code" },
    { key: "DISCOVERING", icon: "⚡", name: "PoC Discoverer", desc: "Generating exploit from code" },
    { key: "EXECUTING", icon: "🐳", name: "Sandbox Executor", desc: "Running exploit in Docker" },
    { key: "JUDGING", icon: "⚖️", name: "LLM Judge", desc: "Interpreting results" },
];

const SAMPLE_VULNS = [
    {
        title: "SQL Injection in Login",
        description: "The login endpoint is vulnerable to SQL injection.",
        vulnerability_type: "SQLi",
        severity: "CRITICAL",
        affected_file: "routes/login.ts",
    },
    {
        title: "JWT Algorithm Confusion",
        description: "The JWT verification allows 'none' algorithm.",
        vulnerability_type: "AuthBypass",
        severity: "CRITICAL",
        affected_file: "lib/insecurity.ts",
    },
];

export default function ValidatePage() {
    const [mode, setMode] = useState<ValidationMode>("batch");

    // Single validation state
    const [formData, setFormData] = useState({
        title: "",
        description: "",
        vulnerability_type: "",
        severity: "",
        affected_file: "",
        source: "manual",
        repo_url: "https://github.com/varun2117/juice-shop",
    });
    const [singleResult, setSingleResult] = useState<SingleResult | null>(null);
    const [singleId, setSingleId] = useState<number | null>(null);

    // Batch validation state
    const [file, setFile] = useState<File | null>(null);
    const [projectPath, setProjectPath] = useState("");
    const [batchResult, setBatchResult] = useState<BatchResult | null>(null);
    const [batchJobId, setBatchJobId] = useState<string | null>(null);

    // Common state
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Poll for single validation
    useEffect(() => {
        if (!singleId) return;

        const poll = setInterval(async () => {
            try {
                const res = await fetch(`${API_URL}/api/validate/${singleId}`);
                const data: SingleResult = await res.json();
                setSingleResult(data);

                if (data.status === "COMPLETED" || data.status === "FAILED") {
                    clearInterval(poll);
                }
            } catch (e) {
                console.error("Polling error:", e);
            }
        }, 1000);

        return () => clearInterval(poll);
    }, [singleId]);

    // Poll for batch validation
    useEffect(() => {
        if (!batchJobId) return;

        const poll = setInterval(async () => {
            try {
                const res = await fetch(`${API_URL}/api/batch/${batchJobId}`);
                const data: BatchResult = await res.json();
                setBatchResult(data);

                if (data.status === "completed" || data.status === "failed") {
                    clearInterval(poll);
                }
            } catch (e) {
                console.error("Polling error:", e);
            }
        }, 2000);

        return () => clearInterval(poll);
    }, [batchJobId]);

    const handleSingleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        setError(null);
        setSingleId(null);
        setSingleResult(null);

        try {
            const res = await fetch(`${API_URL}/api/validate`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(formData),
            });

            if (!res.ok) throw new Error("Failed to submit validation");

            const data = await res.json();
            setSingleId(data.id);
            setSingleResult({ id: data.id, status: "PENDING", verdict: null });
        } catch (e) {
            setError(e instanceof Error ? e.message : "Unknown error");
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleBatchSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!file) {
            setError("Please select a Snyk JSON file");
            return;
        }

        setIsSubmitting(true);
        setError(null);
        setBatchJobId(null);
        setBatchResult(null);

        try {
            const formData = new FormData();
            formData.append("file", file);
            formData.append("project_path", projectPath);

            const res = await fetch(`${API_URL}/api/batch/validate`, {
                method: "POST",
                body: formData,
            });

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || "Failed to submit batch validation");
            }

            const data = await res.json();
            setBatchJobId(data.job_id);
            setBatchResult({
                job_id: data.job_id,
                status: "pending",
                total_alerts: data.total_alerts,
                unique_vulnerabilities: data.unique_vulnerabilities
            });
        } catch (e) {
            setError(e instanceof Error ? e.message : "Unknown error");
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleFileDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        const droppedFile = e.dataTransfer.files[0];
        if (droppedFile?.name.endsWith('.json')) {
            setFile(droppedFile);
        }
    }, []);

    const loadSample = (index: number) => {
        const sample = SAMPLE_VULNS[index];
        setFormData({ ...formData, ...sample });
    };

    const getAgentStatus = (agentKey: string) => {
        if (!singleResult) return "pending";
        const order = AGENTS.map(a => a.key);
        const currentIndex = order.indexOf(singleResult.status);
        const agentIndex = order.indexOf(agentKey);

        if (singleResult.status === "COMPLETED" || singleResult.status === "FAILED") {
            return "complete";
        }
        if (agentIndex < currentIndex) return "complete";
        if (agentIndex === currentIndex) return "active";
        return "pending";
    };

    return (
        <main className="min-h-screen bg-[#0a0a0f]">
            {/* Header */}
            <header className="border-b border-[#1e1e2e] bg-[#111118]/80 backdrop-blur-sm sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                    <Link href="/" className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center">
                            <span className="text-white font-bold text-lg">🛡️</span>
                        </div>
                        <div>
                            <h1 className="text-xl font-bold text-white">PoC Validator</h1>
                            <p className="text-xs text-gray-500">Security Vulnerability Validation</p>
                        </div>
                    </Link>
                    <nav className="flex items-center gap-6">
                        <Link href="/" className="text-gray-400 hover:text-white transition-colors">Home</Link>
                        <Link href="/results" className="text-gray-400 hover:text-white transition-colors">Results</Link>
                    </nav>
                </div>
            </header>

            <div className="max-w-7xl mx-auto px-6 py-12">
                {/* Mode Toggle */}
                <div className="flex gap-4 mb-8">
                    <button
                        onClick={() => setMode("batch")}
                        className={`px-6 py-3 rounded-lg font-medium transition-all ${mode === "batch"
                            ? "bg-gradient-to-r from-emerald-500 to-cyan-500 text-white"
                            : "bg-[#1e1e2e] text-gray-400 hover:text-white"
                            }`}
                    >
                        📁 Batch Upload (Snyk JSON)
                    </button>
                    <button
                        onClick={() => setMode("single")}
                        className={`px-6 py-3 rounded-lg font-medium transition-all ${mode === "single"
                            ? "bg-gradient-to-r from-emerald-500 to-cyan-500 text-white"
                            : "bg-[#1e1e2e] text-gray-400 hover:text-white"
                            }`}
                    >
                        📝 Single Vulnerability
                    </button>
                </div>

                <div className="grid lg:grid-cols-2 gap-12">
                    {/* Left: Form Section */}
                    <div>
                        {mode === "batch" ? (
                            <>
                                <h2 className="text-2xl font-bold text-white mb-2">Upload Snyk Report</h2>
                                <p className="text-gray-400 mb-6">Drop your Snyk JSON export to validate all vulnerabilities</p>

                                <form onSubmit={handleBatchSubmit} className="space-y-6">
                                    {/* File Drop Zone */}
                                    <div
                                        onDrop={handleFileDrop}
                                        onDragOver={(e) => e.preventDefault()}
                                        className={`border-2 border-dashed rounded-xl p-12 text-center transition-colors ${file
                                            ? "border-emerald-500/50 bg-emerald-500/5"
                                            : "border-[#2e2e4e] hover:border-emerald-500/30"
                                            }`}
                                    >
                                        {file ? (
                                            <div className="space-y-2">
                                                <span className="text-4xl">📄</span>
                                                <p className="text-white font-medium">{file.name}</p>
                                                <p className="text-gray-500 text-sm">{(file.size / 1024).toFixed(1)} KB</p>
                                                <button
                                                    type="button"
                                                    onClick={() => setFile(null)}
                                                    className="text-red-400 text-sm hover:underline"
                                                >
                                                    Remove
                                                </button>
                                            </div>
                                        ) : (
                                            <div className="space-y-4">
                                                <span className="text-4xl">📁</span>
                                                <p className="text-gray-400">Drop Snyk JSON file here or</p>
                                                <label className="inline-block px-4 py-2 bg-[#1e1e2e] text-white rounded-lg cursor-pointer hover:bg-[#2a2a3e]">
                                                    Browse Files
                                                    <input
                                                        type="file"
                                                        accept=".json"
                                                        onChange={(e) => setFile(e.target.files?.[0] || null)}
                                                        className="hidden"
                                                    />
                                                </label>
                                            </div>
                                        )}
                                    </div>

                                    {/* Project Path */}
                                    <div>
                                        <label className="block text-sm font-medium text-gray-300 mb-2">
                                            Project Path (optional)
                                        </label>
                                        <input
                                            type="text"
                                            value={projectPath}
                                            onChange={(e) => setProjectPath(e.target.value)}
                                            className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50"
                                            placeholder="/path/to/project (for dependency exploits)"
                                        />
                                        <p className="text-xs text-gray-500 mt-1">
                                            Path to project with node_modules for npm dependency validation
                                        </p>
                                    </div>

                                    {error && (
                                        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
                                            {error}
                                        </div>
                                    )}

                                    <button
                                        type="submit"
                                        disabled={isSubmitting || !file || (batchResult?.status === "running")}
                                        className="w-full py-4 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-semibold rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                                    >
                                        {isSubmitting ? (
                                            <>
                                                <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                                                </svg>
                                                Uploading...
                                            </>
                                        ) : (
                                            <>🚀 Validate All Vulnerabilities</>
                                        )}
                                    </button>
                                </form>
                            </>
                        ) : (
                            <>
                                <h2 className="text-2xl font-bold text-white mb-2">Submit Vulnerability</h2>
                                <p className="text-gray-400 mb-6">Enter vulnerability details to validate</p>

                                <div className="flex gap-2 mb-6">
                                    <span className="text-sm text-gray-500">Quick fill:</span>
                                    {SAMPLE_VULNS.map((v, i) => (
                                        <button
                                            key={i}
                                            onClick={() => loadSample(i)}
                                            className="px-3 py-1 text-xs bg-[#1e1e2e] text-gray-300 rounded hover:bg-[#2a2a3e]"
                                        >
                                            {v.vulnerability_type}
                                        </button>
                                    ))}
                                </div>

                                <form onSubmit={handleSingleSubmit} className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
                                        <input
                                            type="text"
                                            value={formData.title}
                                            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                                            className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50"
                                            placeholder="e.g., SQL Injection in Login"
                                            required
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                                        <textarea
                                            value={formData.description}
                                            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                                            className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50 h-32"
                                            placeholder="Describe the vulnerability..."
                                            required
                                        />
                                    </div>

                                    <button
                                        type="submit"
                                        disabled={isSubmitting}
                                        className="w-full py-4 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-semibold rounded-lg hover:opacity-90 disabled:opacity-50"
                                    >
                                        Start Validation
                                    </button>
                                </form>
                            </>
                        )}
                    </div>

                    {/* Right: Results Section */}
                    <div>
                        {mode === "batch" ? (
                            <>
                                <h2 className="text-2xl font-bold text-white mb-2">Batch Results</h2>
                                <p className="text-gray-400 mb-6">Validation progress and exploitable vulnerabilities</p>

                                {batchResult ? (
                                    <div className="space-y-6">
                                        {/* Status Card */}
                                        <div className={`p-6 rounded-xl border ${batchResult.status === "completed"
                                            ? "border-emerald-500/50 bg-emerald-500/5"
                                            : batchResult.status === "failed"
                                                ? "border-red-500/50 bg-red-500/5"
                                                : "border-[#2e2e4e] bg-[#111118]"
                                            }`}>
                                            <div className="flex items-center justify-between mb-4">
                                                <div>
                                                    <p className="text-gray-400 text-sm">Job ID</p>
                                                    <p className="text-white font-mono">{batchResult.job_id}</p>
                                                </div>
                                                <div className={`px-3 py-1 rounded-full text-sm ${batchResult.status === "completed"
                                                    ? "bg-emerald-500/20 text-emerald-400"
                                                    : batchResult.status === "running"
                                                        ? "bg-amber-500/20 text-amber-400"
                                                        : batchResult.status === "failed"
                                                            ? "bg-red-500/20 text-red-400"
                                                            : "bg-gray-500/20 text-gray-400"
                                                    }`}>
                                                    {batchResult.status === "running" && (
                                                        <span className="inline-block w-2 h-2 bg-amber-400 rounded-full animate-pulse mr-2"></span>
                                                    )}
                                                    {batchResult.status.toUpperCase()}
                                                </div>
                                            </div>

                                            <div className="grid grid-cols-2 gap-4">
                                                <div className="p-3 bg-black/20 rounded-lg">
                                                    <p className="text-gray-500 text-xs">Total Alerts</p>
                                                    <p className="text-2xl font-bold text-white">{batchResult.total_alerts}</p>
                                                </div>
                                                <div className="p-3 bg-black/20 rounded-lg">
                                                    <p className="text-gray-500 text-xs">Unique Packages</p>
                                                    <p className="text-2xl font-bold text-white">{batchResult.unique_vulnerabilities}</p>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Progress Bar - shown while running */}
                                        {batchResult.status === "running" && batchResult.progress && (
                                            <div className="p-6 rounded-xl border border-amber-500/30 bg-amber-500/5">
                                                <div className="flex items-center justify-between mb-2">
                                                    <h3 className="text-lg font-bold text-amber-400">Validating...</h3>
                                                    <span className="text-amber-400 font-mono">
                                                        {batchResult.progress.current} / {batchResult.progress.total}
                                                    </span>
                                                </div>

                                                {/* Progress Bar */}
                                                <div className="w-full bg-[#1e1e2e] rounded-full h-3 mb-4">
                                                    <div
                                                        className="bg-gradient-to-r from-amber-500 to-emerald-500 h-3 rounded-full transition-all duration-300"
                                                        style={{ width: `${(batchResult.progress.current / batchResult.progress.total) * 100}%` }}
                                                    />
                                                </div>

                                                {/* Current Package */}
                                                {batchResult.progress.current_package && (
                                                    <div className="flex items-center gap-2 mb-4">
                                                        <svg className="animate-spin w-4 h-4 text-amber-400" fill="none" viewBox="0 0 24 24">
                                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                                                        </svg>
                                                        <span className="text-gray-400">Currently testing:</span>
                                                        <span className="text-white font-medium">{batchResult.progress.current_package}</span>
                                                    </div>
                                                )}

                                                {/* Completed Items */}
                                                {batchResult.progress.completed && batchResult.progress.completed.length > 0 && (
                                                    <div className="max-h-48 overflow-y-auto space-y-1">
                                                        {batchResult.progress.completed.slice(-8).reverse().map((item, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-sm p-2 bg-black/20 rounded">
                                                                <span className={
                                                                    item.verdict === "exploitable" ? "text-red-400" :
                                                                        item.verdict === "false_positive" ? "text-emerald-400" :
                                                                            "text-amber-400"
                                                                }>
                                                                    {item.verdict === "exploitable" ? "🔴" :
                                                                        item.verdict === "false_positive" ? "🟢" : "🟡"}
                                                                </span>
                                                                <span className="text-white font-medium">{item.package}</span>
                                                                <span className="text-gray-500 text-xs truncate flex-1">{item.reason}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Summary */}

                                        {batchResult.summary && (
                                            <div className="p-6 rounded-xl border border-[#2e2e4e] bg-[#111118]">
                                                <h3 className="text-lg font-bold text-white mb-4">Summary</h3>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                                                        <p className="text-red-400 text-xs uppercase">Exploitable</p>
                                                        <p className="text-3xl font-bold text-red-400">{batchResult.summary.exploitable_count}</p>
                                                    </div>
                                                    <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                                                        <p className="text-emerald-400 text-xs uppercase">False Positives</p>
                                                        <p className="text-3xl font-bold text-emerald-400">
                                                            {batchResult.summary.by_verdict?.false_positive || 0}
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>
                                        )}

                                        {/* Exploitable List */}
                                        {batchResult.exploitable && batchResult.exploitable.length > 0 && (
                                            <div className="p-6 rounded-xl border border-red-500/30 bg-red-500/5">
                                                <h3 className="text-lg font-bold text-red-400 mb-4">
                                                    🚨 Exploitable ({batchResult.exploitable.length})
                                                </h3>
                                                <div className="space-y-2 max-h-64 overflow-y-auto">
                                                    {batchResult.exploitable.map((item, i) => (
                                                        <div key={i} className="flex items-center justify-between p-3 bg-black/30 rounded-lg">
                                                            <div>
                                                                <span className={`text-xs px-2 py-0.5 rounded mr-2 ${item.severity === "CRITICAL" ? "bg-red-500 text-white" :
                                                                    item.severity === "HIGH" ? "bg-orange-500 text-white" :
                                                                        "bg-yellow-500 text-black"
                                                                    }`}>
                                                                    {item.severity}
                                                                </span>
                                                                <span className="text-white font-medium">{item.package}</span>
                                                            </div>
                                                            <span className="text-xs text-gray-500">{item.exploit_source}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {batchResult.error && (
                                            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
                                                Error: {batchResult.error}
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="p-12 rounded-xl border border-[#2e2e4e] bg-[#111118] text-center">
                                        <span className="text-4xl">📊</span>
                                        <p className="text-gray-400 mt-4">Upload a Snyk JSON file to see results</p>
                                    </div>
                                )}
                            </>
                        ) : (
                            <>
                                <h2 className="text-2xl font-bold text-white mb-2">Validation Progress</h2>
                                <p className="text-gray-400 mb-6">Watch the 5-agent pipeline</p>

                                <div className="space-y-4 mb-8">
                                    {AGENTS.map((agent, i) => {
                                        const status = getAgentStatus(agent.key);
                                        return (
                                            <div key={i} className={`p-4 rounded-xl border transition-all ${status === "active" ? "bg-emerald-500/10 border-emerald-500/50" :
                                                status === "complete" ? "bg-[#111118] border-emerald-500/30" :
                                                    "bg-[#111118] border-[#1e1e2e]"
                                                }`}>
                                                <div className="flex items-center gap-4">
                                                    <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${status === "active" ? "bg-emerald-500/20" :
                                                        status === "complete" ? "bg-emerald-500/20" : "bg-[#1e1e2e]"
                                                        }`}>
                                                        {status === "complete" ? "✓" : agent.icon}
                                                    </div>
                                                    <div>
                                                        <h4 className={`font-medium ${status === "active" ? "text-emerald-400" :
                                                            status === "complete" ? "text-white" : "text-gray-500"
                                                            }`}>{agent.name}</h4>
                                                        <p className="text-sm text-gray-500">{agent.desc}</p>
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>

                                {singleResult?.verdict && (
                                    <div className={`p-6 rounded-xl border ${singleResult.verdict === "VALID" ? "border-emerald-500/50 bg-emerald-500/10" :
                                        singleResult.verdict === "INVALID" ? "border-red-500/50 bg-red-500/10" :
                                            "border-amber-500/50 bg-amber-500/10"
                                        }`}>
                                        <h3 className="text-2xl font-bold mb-2">{singleResult.verdict}</h3>
                                        {singleResult.judge_reasoning && (
                                            <p className="text-sm opacity-75">{singleResult.judge_reasoning}</p>
                                        )}
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                </div>
            </div>
        </main>
    );
}
