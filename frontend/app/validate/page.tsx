"use client";

import { useState, useEffect } from "react";
import Link from "next/link";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type ValidationStatus =
    | "PENDING"
    | "PARSING"
    | "ANALYZING"
    | "DISCOVERING"
    | "EXECUTING"
    | "JUDGING"
    | "COMPLETED"
    | "FAILED";

type Verdict = "VALID" | "INVALID" | "NEEDS_REVIEW" | null;

interface ValidationResult {
    id: number;
    status: ValidationStatus;
    verdict: Verdict;
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
    started_at?: string;
    completed_at?: string;
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
        description: "The login endpoint is vulnerable to SQL injection. An attacker can bypass authentication by injecting SQL code in the email field.",
        vulnerability_type: "SQLi",
        severity: "CRITICAL",
        affected_file: "routes/login.ts",
    },
    {
        title: "Reflected XSS in Search",
        description: "The search functionality reflects user input without sanitization, allowing XSS attacks.",
        vulnerability_type: "XSS",
        severity: "HIGH",
        affected_file: "routes/search.ts",
    },
    {
        title: "JWT Algorithm Confusion",
        description: "The JWT verification allows 'none' algorithm, enabling authentication bypass.",
        vulnerability_type: "AuthBypass",
        severity: "CRITICAL",
        affected_file: "lib/insecurity.ts",
    },
];

export default function ValidatePage() {
    const [formData, setFormData] = useState({
        title: "",
        description: "",
        vulnerability_type: "",
        severity: "",
        affected_file: "",
        source: "manual",
        repo_url: "https://github.com/varun2117/juice-shop",
    });

    const [validationId, setValidationId] = useState<number | null>(null);
    const [result, setResult] = useState<ValidationResult | null>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Poll for status updates
    useEffect(() => {
        if (!validationId) return;

        const poll = setInterval(async () => {
            try {
                const res = await fetch(`${API_URL}/api/validate/${validationId}`);
                const data: ValidationResult = await res.json();
                setResult(data);

                if (data.status === "COMPLETED" || data.status === "FAILED") {
                    clearInterval(poll);
                }
            } catch (e) {
                console.error("Polling error:", e);
            }
        }, 1000);

        return () => clearInterval(poll);
    }, [validationId]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        setError(null);
        setValidationId(null);
        setResult(null);

        try {
            const res = await fetch(`${API_URL}/api/validate`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(formData),
            });

            if (!res.ok) throw new Error("Failed to submit validation");

            const data = await res.json();
            setValidationId(data.id);
            setResult({ id: data.id, status: "PENDING", verdict: null });
        } catch (e) {
            setError(e instanceof Error ? e.message : "Unknown error");
        } finally {
            setIsSubmitting(false);
        }
    };

    const loadSample = (index: number) => {
        const sample = SAMPLE_VULNS[index];
        setFormData({ ...formData, ...sample });
    };

    const getAgentStatus = (agentKey: string) => {
        if (!result) return "pending";

        const order = AGENTS.map(a => a.key);
        const currentIndex = order.indexOf(result.status);
        const agentIndex = order.indexOf(agentKey);

        if (result.status === "COMPLETED" || result.status === "FAILED") {
            return agentIndex <= order.indexOf("JUDGING") ? "complete" : "pending";
        }

        if (agentIndex < currentIndex) return "complete";
        if (agentIndex === currentIndex) return "active";
        return "pending";
    };

    const getVerdictColor = (verdict: Verdict) => {
        switch (verdict) {
            case "VALID": return "text-emerald-400 border-emerald-500/50 bg-emerald-500/10";
            case "INVALID": return "text-red-400 border-red-500/50 bg-red-500/10";
            case "NEEDS_REVIEW": return "text-amber-400 border-amber-500/50 bg-amber-500/10";
            default: return "text-gray-400 border-gray-500/50 bg-gray-500/10";
        }
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
                </div>
            </header>

            <div className="max-w-7xl mx-auto px-6 py-12">
                <div className="grid lg:grid-cols-2 gap-12">
                    {/* Form Section */}
                    <div>
                        <h2 className="text-2xl font-bold text-white mb-2">Submit Vulnerability</h2>
                        <p className="text-gray-400 mb-6">Enter vulnerability details to validate</p>

                        {/* GitHub Repo Input */}
                        <div className="mb-6 p-4 rounded-xl bg-[#111118] border border-[#1e1e2e]">
                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                <span className="flex items-center gap-2">
                                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" /></svg>
                                    GitHub Repository
                                </span>
                            </label>
                            <input
                                type="text"
                                value={formData.repo_url}
                                onChange={e => setFormData({ ...formData, repo_url: e.target.value })}
                                className="w-full px-4 py-3 bg-[#0a0a0f] border border-[#2e2e4e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50 font-mono text-sm"
                                placeholder="https://github.com/owner/repo"
                            />
                        </div>

                        {/* Sample Buttons */}
                        <div className="flex gap-2 mb-6">
                            <span className="text-sm text-gray-500">Quick fill:</span>
                            {SAMPLE_VULNS.map((v, i) => (
                                <button
                                    key={i}
                                    onClick={() => loadSample(i)}
                                    className="px-3 py-1 text-xs bg-[#1e1e2e] text-gray-300 rounded hover:bg-[#2a2a3e] transition-colors"
                                >
                                    {v.vulnerability_type}
                                </button>
                            ))}
                        </div>

                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
                                <input
                                    type="text"
                                    value={formData.title}
                                    onChange={e => setFormData({ ...formData, title: e.target.value })}
                                    className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50"
                                    placeholder="e.g., SQL Injection in Login"
                                    required
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                                <textarea
                                    value={formData.description}
                                    onChange={e => setFormData({ ...formData, description: e.target.value })}
                                    className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50 h-32"
                                    placeholder="Describe the vulnerability and how it can be exploited..."
                                    required
                                />
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Type</label>
                                    <select
                                        value={formData.vulnerability_type}
                                        onChange={e => setFormData({ ...formData, vulnerability_type: e.target.value })}
                                        className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50"
                                    >
                                        <option value="">Select type...</option>
                                        <option value="SQLi">SQL Injection</option>
                                        <option value="XSS">Cross-Site Scripting</option>
                                        <option value="AuthBypass">Auth Bypass</option>
                                        <option value="IDOR">IDOR</option>
                                        <option value="PathTraversal">Path Traversal</option>
                                        <option value="RCE">Remote Code Execution</option>
                                    </select>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Severity</label>
                                    <select
                                        value={formData.severity}
                                        onChange={e => setFormData({ ...formData, severity: e.target.value })}
                                        className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50"
                                    >
                                        <option value="">Select severity...</option>
                                        <option value="CRITICAL">Critical</option>
                                        <option value="HIGH">High</option>
                                        <option value="MEDIUM">Medium</option>
                                        <option value="LOW">Low</option>
                                    </select>
                                </div>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-2">Affected File (optional)</label>
                                <input
                                    type="text"
                                    value={formData.affected_file}
                                    onChange={e => setFormData({ ...formData, affected_file: e.target.value })}
                                    className="w-full px-4 py-3 bg-[#111118] border border-[#1e1e2e] rounded-lg text-white focus:outline-none focus:border-emerald-500/50"
                                    placeholder="e.g., routes/login.ts"
                                />
                            </div>

                            {error && (
                                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
                                    {error}
                                </div>
                            )}

                            <button
                                type="submit"
                                disabled={isSubmitting || (result && result.status !== "COMPLETED" && result.status !== "FAILED")}
                                className="w-full py-4 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-semibold rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                            >
                                {isSubmitting ? (
                                    <>
                                        <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                        </svg>
                                        Submitting...
                                    </>
                                ) : (
                                    <>
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                        Start Validation
                                    </>
                                )}
                            </button>
                        </form>
                    </div>

                    {/* Results Section */}
                    <div>
                        <h2 className="text-2xl font-bold text-white mb-2">Validation Progress</h2>
                        <p className="text-gray-400 mb-6">Watch the 5-agent pipeline process your vulnerability</p>

                        {/* Agent Pipeline */}
                        <div className="space-y-4 mb-8">
                            {AGENTS.map((agent, i) => {
                                const status = getAgentStatus(agent.key);
                                return (
                                    <div key={i} className={`p-4 rounded-xl border transition-all duration-300 ${status === "active"
                                        ? "bg-emerald-500/10 border-emerald-500/50"
                                        : status === "complete"
                                            ? "bg-[#111118] border-emerald-500/30"
                                            : "bg-[#111118] border-[#1e1e2e]"
                                        }`}>
                                        <div className="flex items-center gap-4">
                                            <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${status === "active"
                                                ? "bg-emerald-500/20 animate-pulse-glow"
                                                : status === "complete"
                                                    ? "bg-emerald-500/20"
                                                    : "bg-[#1e1e2e]"
                                                }`}>
                                                {status === "complete" ? (
                                                    <span className="text-emerald-400">✓</span>
                                                ) : (
                                                    <span className="text-xl">{agent.icon}</span>
                                                )}
                                            </div>
                                            <div className="flex-1">
                                                <h4 className={`font-medium ${status === "active" ? "text-emerald-400" :
                                                    status === "complete" ? "text-white" : "text-gray-500"
                                                    }`}>
                                                    {agent.name}
                                                </h4>
                                                <p className="text-sm text-gray-500">{agent.desc}</p>
                                            </div>
                                            {status === "active" && (
                                                <svg className="animate-spin w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24">
                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                </svg>
                                            )}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>

                        {/* Verdict */}
                        {result?.verdict && (
                            <div className={`p-6 rounded-xl border ${getVerdictColor(result.verdict)}`}>
                                <div className="flex items-center gap-4 mb-4">
                                    <span className="text-4xl">
                                        {result.verdict === "VALID" ? "✅" : result.verdict === "INVALID" ? "❌" : "⚠️"}
                                    </span>
                                    <div>
                                        <h3 className="text-2xl font-bold">{result.verdict}</h3>
                                        <p className="text-sm opacity-75">
                                            {result.verdict === "VALID"
                                                ? "Vulnerability confirmed exploitable"
                                                : result.verdict === "INVALID"
                                                    ? "Not exploitable - likely false positive"
                                                    : "Requires manual review"}
                                        </p>
                                    </div>
                                </div>

                                {result.judge_reasoning && (
                                    <div className="mt-4 p-4 bg-black/20 rounded-lg">
                                        <h4 className="text-sm font-medium mb-2">Judge Reasoning:</h4>
                                        <p className="text-sm opacity-75">{result.judge_reasoning}</p>
                                    </div>
                                )}

                                {result.exploit_name && (
                                    <div className="mt-4 text-sm opacity-75">
                                        <strong>Exploit Used:</strong> {result.exploit_name}
                                    </div>
                                )}
                            </div>
                        )}

                        {result?.status === "FAILED" && (
                            <div className="p-6 rounded-xl border border-red-500/50 bg-red-500/10">
                                <div className="flex items-center gap-4">
                                    <span className="text-4xl">💥</span>
                                    <div>
                                        <h3 className="text-2xl font-bold text-red-400">Validation Failed</h3>
                                        <p className="text-sm text-gray-400">An error occurred during the validation process</p>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </main>
    );
}
