"use client";

import { useState, useEffect } from "react";
import Link from "next/link";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface BatchJob {
    job_id: string;
    status: string;
    total_alerts: number;
    unique_vulnerabilities: number;
    created_at: string;
    completed_at?: string;
    summary?: {
        exploitable_count: number;
        by_verdict: Record<string, number>;
    };
    exploitable?: Array<{
        package: string;
        title: string;
        severity: string;
    }>;
    error?: string;
}

export default function ResultsPage() {
    const [jobs, setJobs] = useState<BatchJob[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedJob, setSelectedJob] = useState<BatchJob | null>(null);

    useEffect(() => {
        fetchJobs();
    }, []);

    const fetchJobs = async () => {
        try {
            const res = await fetch(`${API_URL}/api/batch`);
            const data = await res.json();
            setJobs(data.jobs || []);
        } catch (e) {
            console.error("Failed to fetch jobs:", e);
        } finally {
            setLoading(false);
        }
    };

    const getStatusBadge = (job: BatchJob) => {
        switch (job.status) {
            case "completed":
                const exploitable = job.summary?.exploitable_count || 0;
                return (
                    <span className={`px-3 py-1 text-xs rounded-full ${exploitable > 0 ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>
                        {exploitable > 0 ? `🔴 ${exploitable} Exploitable` : '🟢 All Safe'}
                    </span>
                );
            case "running":
                return (
                    <span className="px-3 py-1 text-xs rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">
                        🔄 Running
                    </span>
                );
            case "failed":
                return (
                    <span className="px-3 py-1 text-xs rounded-full bg-red-500/20 text-red-400 border border-red-500/30">
                        ❌ Failed
                    </span>
                );
            default:
                return (
                    <span className="px-3 py-1 text-xs rounded-full bg-gray-500/20 text-gray-400 border border-gray-500/30">
                        ⏳ Pending
                    </span>
                );
        }
    };

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString();
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
                    <div className="flex items-center gap-4">
                        <Link href="/validate" className="text-gray-400 hover:text-white transition-colors">
                            Validate
                        </Link>
                        <Link href="/results" className="text-white font-medium">
                            Results
                        </Link>
                    </div>
                </div>
            </header>

            <div className="max-w-7xl mx-auto px-6 py-12">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-2xl font-bold text-white">Validation Results</h2>
                        <p className="text-gray-400">All batch validation jobs</p>
                    </div>
                    <button
                        onClick={fetchJobs}
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
                ) : jobs.length === 0 ? (
                    <div className="text-center py-24">
                        <div className="w-16 h-16 rounded-full bg-[#1e1e2e] flex items-center justify-center mx-auto mb-4">
                            <span className="text-3xl">📋</span>
                        </div>
                        <h3 className="text-xl font-medium text-white mb-2">No validations yet</h3>
                        <p className="text-gray-400 mb-6">Upload a Snyk report to get started</p>
                        <Link
                            href="/validate"
                            className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-medium rounded-lg hover:opacity-90 transition-opacity"
                        >
                            Start Validation
                        </Link>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Jobs List */}
                        <div className="lg:col-span-1 space-y-4">
                            {jobs.map((job) => (
                                <div
                                    key={job.job_id}
                                    onClick={() => setSelectedJob(job)}
                                    className={`p-4 rounded-xl bg-[#111118] border cursor-pointer transition-all ${selectedJob?.job_id === job.job_id ? 'border-emerald-500' : 'border-[#1e1e2e] hover:border-[#2e2e4e]'}`}
                                >
                                    <div className="flex items-center justify-between mb-2">
                                        <span className="text-sm font-mono text-gray-500">{job.job_id}</span>
                                        {getStatusBadge(job)}
                                    </div>
                                    <div className="text-sm text-gray-400">
                                        <span>{job.unique_vulnerabilities} packages</span>
                                        <span className="mx-2">•</span>
                                        <span>{formatDate(job.created_at)}</span>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Job Details */}
                        <div className="lg:col-span-2">
                            {selectedJob ? (
                                <div className="p-6 rounded-xl bg-[#111118] border border-[#1e1e2e]">
                                    <div className="flex items-center justify-between mb-6">
                                        <h3 className="text-lg font-bold text-white">Job {selectedJob.job_id}</h3>
                                        {getStatusBadge(selectedJob)}
                                    </div>

                                    {/* Summary Stats */}
                                    {selectedJob.summary && (
                                        <div className="grid grid-cols-3 gap-4 mb-6">
                                            <div className="p-4 rounded-lg bg-[#1e1e2e]">
                                                <div className="text-2xl font-bold text-red-400">{selectedJob.summary.exploitable_count}</div>
                                                <div className="text-xs text-gray-500">Exploitable</div>
                                            </div>
                                            <div className="p-4 rounded-lg bg-[#1e1e2e]">
                                                <div className="text-2xl font-bold text-emerald-400">{selectedJob.summary.by_verdict?.false_positive || 0}</div>
                                                <div className="text-xs text-gray-500">False Positives</div>
                                            </div>
                                            <div className="p-4 rounded-lg bg-[#1e1e2e]">
                                                <div className="text-2xl font-bold text-amber-400">{selectedJob.summary.by_verdict?.needs_review || 0}</div>
                                                <div className="text-xs text-gray-500">Needs Review</div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Error */}
                                    {selectedJob.error && (
                                        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 mb-6">
                                            <div className="text-sm text-red-400 font-medium mb-1">Error</div>
                                            <div className="text-sm text-red-300">{selectedJob.error}</div>
                                        </div>
                                    )}

                                    {/* Exploitable Packages */}
                                    {selectedJob.exploitable && selectedJob.exploitable.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-medium text-gray-400 mb-3">Exploitable Packages</h4>
                                            <div className="space-y-2">
                                                {selectedJob.exploitable.map((pkg, i) => (
                                                    <div key={i} className="p-3 rounded-lg bg-[#1e1e2e] flex items-center justify-between">
                                                        <div>
                                                            <span className="text-white font-medium">{pkg.package}</span>
                                                            <span className="text-gray-500 text-sm ml-2">{pkg.title}</span>
                                                        </div>
                                                        <span className={`px-2 py-1 text-xs rounded ${pkg.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : pkg.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                                                            {pkg.severity}
                                                        </span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Timestamps */}
                                    <div className="mt-6 pt-4 border-t border-[#1e1e2e] text-xs text-gray-500">
                                        <div>Created: {formatDate(selectedJob.created_at)}</div>
                                        {selectedJob.completed_at && <div>Completed: {formatDate(selectedJob.completed_at)}</div>}
                                    </div>
                                </div>
                            ) : (
                                <div className="p-12 rounded-xl bg-[#111118] border border-[#1e1e2e] text-center">
                                    <span className="text-4xl">👈</span>
                                    <p className="text-gray-400 mt-4">Select a job to view details</p>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </main>
    );
}
