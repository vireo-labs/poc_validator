"use client";

import { useState, useEffect } from "react";
import Link from "next/link";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ValidationSummary {
    id: number;
    status: string;
    verdict: string | null;
    title: string;
}

export default function ResultsPage() {
    const [validations, setValidations] = useState<ValidationSummary[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchValidations();
    }, []);

    const fetchValidations = async () => {
        try {
            const res = await fetch(`${API_URL}/api/validations`);
            const data = await res.json();
            setValidations(data.validations || []);
        } catch (e) {
            console.error("Failed to fetch validations:", e);
        } finally {
            setLoading(false);
        }
    };

    const getVerdictBadge = (verdict: string | null, status: string) => {
        if (status !== "COMPLETED") {
            return (
                <span className="px-3 py-1 text-xs rounded-full bg-gray-500/20 text-gray-400 border border-gray-500/30">
                    {status}
                </span>
            );
        }

        switch (verdict) {
            case "VALID":
                return (
                    <span className="px-3 py-1 text-xs rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        ✅ VALID
                    </span>
                );
            case "INVALID":
                return (
                    <span className="px-3 py-1 text-xs rounded-full bg-red-500/20 text-red-400 border border-red-500/30">
                        ❌ INVALID
                    </span>
                );
            case "NEEDS_REVIEW":
                return (
                    <span className="px-3 py-1 text-xs rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">
                        ⚠️ NEEDS REVIEW
                    </span>
                );
            default:
                return (
                    <span className="px-3 py-1 text-xs rounded-full bg-gray-500/20 text-gray-400 border border-gray-500/30">
                        Unknown
                    </span>
                );
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
                    <Link
                        href="/validate"
                        className="px-4 py-2 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-medium rounded-lg hover:opacity-90 transition-opacity text-sm"
                    >
                        + New Validation
                    </Link>
                </div>
            </header>

            <div className="max-w-7xl mx-auto px-6 py-12">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-2xl font-bold text-white">Validation Results</h2>
                        <p className="text-gray-400">All vulnerability validation attempts</p>
                    </div>
                    <button
                        onClick={fetchValidations}
                        className="px-4 py-2 bg-[#1e1e2e] text-gray-300 rounded-lg hover:bg-[#2a2a3e] transition-colors text-sm flex items-center gap-2"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                        Refresh
                    </button>
                </div>

                {loading ? (
                    <div className="flex items-center justify-center py-24">
                        <svg className="animate-spin w-8 h-8 text-emerald-400" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                    </div>
                ) : validations.length === 0 ? (
                    <div className="text-center py-24">
                        <div className="w-16 h-16 rounded-full bg-[#1e1e2e] flex items-center justify-center mx-auto mb-4">
                            <span className="text-3xl">📋</span>
                        </div>
                        <h3 className="text-xl font-medium text-white mb-2">No validations yet</h3>
                        <p className="text-gray-400 mb-6">Submit your first vulnerability to get started</p>
                        <Link
                            href="/validate"
                            className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-medium rounded-lg hover:opacity-90 transition-opacity"
                        >
                            Start Validation
                        </Link>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {validations.map((v) => (
                            <div
                                key={v.id}
                                className="p-6 rounded-xl bg-[#111118] border border-[#1e1e2e] hover:border-[#2e2e4e] transition-colors"
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className="w-12 h-12 rounded-lg bg-[#1e1e2e] flex items-center justify-center">
                                            <span className="text-xl">
                                                {v.verdict === "VALID" ? "✅" : v.verdict === "INVALID" ? "❌" : v.verdict === "NEEDS_REVIEW" ? "⚠️" : "🔄"}
                                            </span>
                                        </div>
                                        <div>
                                            <h3 className="text-lg font-medium text-white">{v.title || `Validation #${v.id}`}</h3>
                                            <p className="text-sm text-gray-500">ID: {v.id}</p>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-4">
                                        {getVerdictBadge(v.verdict, v.status)}
                                        <Link
                                            href={`/validate?id=${v.id}`}
                                            className="px-4 py-2 bg-[#1e1e2e] text-gray-300 rounded-lg hover:bg-[#2a2a3e] transition-colors text-sm"
                                        >
                                            View Details
                                        </Link>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Stats */}
                {validations.length > 0 && (
                    <div className="mt-12 grid grid-cols-4 gap-6">
                        <div className="p-6 rounded-xl bg-[#111118] border border-[#1e1e2e]">
                            <div className="text-3xl font-bold text-white mb-1">{validations.length}</div>
                            <div className="text-sm text-gray-500">Total Validations</div>
                        </div>
                        <div className="p-6 rounded-xl bg-[#111118] border border-emerald-500/30">
                            <div className="text-3xl font-bold text-emerald-400 mb-1">
                                {validations.filter(v => v.verdict === "VALID").length}
                            </div>
                            <div className="text-sm text-gray-500">Confirmed Exploitable</div>
                        </div>
                        <div className="p-6 rounded-xl bg-[#111118] border border-red-500/30">
                            <div className="text-3xl font-bold text-red-400 mb-1">
                                {validations.filter(v => v.verdict === "INVALID").length}
                            </div>
                            <div className="text-sm text-gray-500">False Positives</div>
                        </div>
                        <div className="p-6 rounded-xl bg-[#111118] border border-amber-500/30">
                            <div className="text-3xl font-bold text-amber-400 mb-1">
                                {validations.filter(v => v.verdict === "NEEDS_REVIEW").length}
                            </div>
                            <div className="text-sm text-gray-500">Needs Review</div>
                        </div>
                    </div>
                )}
            </div>
        </main>
    );
}
