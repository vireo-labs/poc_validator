"use client";

import { useState } from "react";
import Link from "next/link";

export default function Home() {
  return (
    <main className="min-h-screen bg-[#0a0a0f]">
      {/* Header */}
      <header className="border-b border-[#1e1e2e] bg-[#111118]/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center">
              <span className="text-white font-bold text-lg">🛡️</span>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">PoC Validator</h1>
              <p className="text-xs text-gray-500">Security Vulnerability Validation</p>
            </div>
          </div>
          <nav className="flex items-center gap-6">
            <Link href="/validate" className="text-gray-400 hover:text-white transition-colors">
              Validate
            </Link>
            <Link href="/results" className="text-gray-400 hover:text-white transition-colors">
              Results
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="max-w-7xl mx-auto px-6 py-24 text-center">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm mb-8">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          Powered by OWASP Juice Shop
        </div>
        
        <h2 className="text-5xl md:text-6xl font-bold text-white mb-6 leading-tight">
          Validate Vulnerabilities<br />
          <span className="gradient-text">Automatically</span>
        </h2>
        
        <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-12">
          Submit security scanner alerts and we'll run real exploits in isolated sandboxes 
          to prove which vulnerabilities are actually exploitable.
        </p>

        <div className="flex items-center justify-center gap-4">
          <Link 
            href="/validate"
            className="px-8 py-4 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-semibold rounded-lg hover:opacity-90 transition-opacity flex items-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Start Validation
          </Link>
          <Link 
            href="/results"
            className="px-8 py-4 bg-[#1e1e2e] text-white font-semibold rounded-lg hover:bg-[#2a2a3e] transition-colors border border-[#2e2e4e]"
          >
            View Results
          </Link>
        </div>
      </section>

      {/* Pipeline Section */}
      <section className="max-w-7xl mx-auto px-6 py-16">
        <h3 className="text-2xl font-bold text-white text-center mb-12">5-Agent Validation Pipeline</h3>
        
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          {[
            { icon: "📄", name: "Report Parser", desc: "Extract vulnerability details" },
            { icon: "🔍", name: "Code Analyzer", desc: "Verify vulnerable code" },
            { icon: "⚡", name: "PoC Discoverer", desc: "Find/generate exploit" },
            { icon: "🐳", name: "Sandbox Executor", desc: "Run in isolated Docker" },
            { icon: "⚖️", name: "LLM Judge", desc: "Interpret & verdict" },
          ].map((agent, i) => (
            <div key={i} className="flex items-center gap-4">
              <div className="w-20 h-20 rounded-xl bg-[#111118] border border-[#1e1e2e] flex flex-col items-center justify-center p-3 hover:border-emerald-500/50 transition-colors">
                <span className="text-2xl mb-1">{agent.icon}</span>
                <span className="text-xs text-gray-400 text-center leading-tight">{agent.name}</span>
              </div>
              {i < 4 && (
                <svg className="w-6 h-6 text-gray-600 hidden md:block" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Verdict Cards */}
      <section className="max-w-7xl mx-auto px-6 py-16">
        <h3 className="text-2xl font-bold text-white text-center mb-12">Clear Verdicts, No Guesswork</h3>
        
        <div className="grid md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl bg-[#111118] border border-emerald-500/30 glow-success">
            <div className="w-12 h-12 rounded-lg bg-emerald-500/20 flex items-center justify-center mb-4">
              <span className="text-2xl">✅</span>
            </div>
            <h4 className="text-lg font-semibold text-emerald-400 mb-2">VALID</h4>
            <p className="text-gray-400">Vulnerability confirmed exploitable. Prioritize immediate patching.</p>
          </div>
          
          <div className="p-6 rounded-xl bg-[#111118] border border-red-500/30 glow-danger">
            <div className="w-12 h-12 rounded-lg bg-red-500/20 flex items-center justify-center mb-4">
              <span className="text-2xl">❌</span>
            </div>
            <h4 className="text-lg font-semibold text-red-400 mb-2">INVALID</h4>
            <p className="text-gray-400">Not exploitable. Likely a false positive from the scanner.</p>
          </div>
          
          <div className="p-6 rounded-xl bg-[#111118] border border-amber-500/30 glow-warning">
            <div className="w-12 h-12 rounded-lg bg-amber-500/20 flex items-center justify-center mb-4">
              <span className="text-2xl">⚠️</span>
            </div>
            <h4 className="text-lg font-semibold text-amber-400 mb-2">NEEDS REVIEW</h4>
            <p className="text-gray-400">Inconclusive results. Requires manual security review.</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#1e1e2e] py-8 mt-16">
        <div className="max-w-7xl mx-auto px-6 text-center text-gray-500 text-sm">
          <p>PoC Validator V0 Demo • Powered by OWASP Juice Shop • OpenRouter API</p>
        </div>
      </footer>
    </main>
  );
}
