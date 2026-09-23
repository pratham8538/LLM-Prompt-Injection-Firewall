import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  Play,
  RefreshCw,
  Award,
  AlertTriangle,
  Zap,
  Layers,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';
import { TestSuiteItem } from '../types';
import { getTestSuiteApi, runTestSuiteApi } from '../lib/api';

export const TestSuiteRunner: React.FC = () => {
  const [tests, setTests] = useState<TestSuiteItem[]>([]);
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState<{
    passedCount: number;
    failedCount: number;
    total: number;
    accuracyPercent: number;
    falsePositiveCount: number;
    falseNegativeCount: number;
  } | null>(null);

  const fetchTests = async () => {
    try {
      const data = await getTestSuiteApi();
      setTests(data);
    } catch (err) {
      console.error('Failed to load test suite', err);
    }
  };

  useEffect(() => {
    fetchTests();
  }, []);

  const handleRunTests = async () => {
    setRunning(true);
    try {
      const data = await runTestSuiteApi();
      setTests(data.results);
      setSummary({
        passedCount: data.passedCount,
        failedCount: data.failedCount,
        total: data.total,
        accuracyPercent: data.accuracyPercent,
        falsePositiveCount: data.falsePositiveCount,
        falseNegativeCount: data.falseNegativeCount,
      });
    } catch (err) {
      console.error('Failed to run test suite', err);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* High Density Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white rounded-xl shadow-sm border border-slate-200 p-5">
        <div>
          <h2 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-0.5">
            Validation Harness
          </h2>
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-blue-600" />
            <span>Automated Benchmark Matrix & Verification Suite</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Executes PRD benchmark suite: Safe queries, Direct overrides, Jailbreaks, and Encoded attacks.
          </p>
        </div>

        <button
          id="run-all-tests-btn"
          onClick={handleRunTests}
          disabled={running}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold shadow-sm transition-all cursor-pointer self-start disabled:opacity-50"
        >
          {running ? (
            <>
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              <span>Executing Matrix...</span>
            </>
          ) : (
            <>
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>Run Full Evaluation Suite</span>
            </>
          )}
        </button>
      </div>

      {/* Summary Scorecard */}
      {summary && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-[10px] font-bold text-slate-400 uppercase mb-1">Overall Accuracy</div>
            <div className="text-2xl font-black text-emerald-600">{summary.accuracyPercent}%</div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              {summary.passedCount} of {summary.total} tests passed
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-[10px] font-bold text-slate-400 uppercase mb-1">False Positives (FPR)</div>
            <div className="text-2xl font-black text-slate-900">{summary.falsePositiveCount}</div>
            <div className="text-[11px] text-slate-500 mt-0.5">Legitimate queries blocked</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-[10px] font-bold text-slate-400 uppercase mb-1">False Negatives (FNR)</div>
            <div className="text-2xl font-black text-slate-900">{summary.falseNegativeCount}</div>
            <div className="text-[11px] text-slate-500 mt-0.5">Attacks missed by engine</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-[10px] font-bold text-slate-400 uppercase mb-1">Classification</div>
            <div className="text-2xl font-black text-blue-600">
              {summary.accuracyPercent >= 90 ? 'PASSED (A+)' : 'TUNING_NEEDED'}
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">Meets PRD threshold targets</div>
          </div>
        </div>
      )}

      {/* Test Matrix List Styled as High Density Milestone Cards */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm p-5 space-y-3">
        <div className="border-b border-slate-100 pb-3 flex items-center justify-between">
          <div>
            <h2 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-0.5">
              Test Registry
            </h2>
            <h3 className="font-bold text-sm text-slate-900">
              Benchmark Test Cases ({tests.length} vectors)
            </h3>
          </div>
        </div>

        <div className="space-y-3">
          {tests.map((test, index) => {
            const hasResult = !!test.lastResult;
            const passed = test.lastResult?.passed;

            return (
              <div
                key={test.id}
                className={`flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4 p-3.5 rounded-lg border transition-all ${
                  hasResult
                    ? passed
                      ? 'border-l-4 border-l-emerald-500 border-slate-200 bg-emerald-50/30'
                      : 'border-l-4 border-l-rose-500 border-slate-200 bg-rose-50/30'
                    : 'border-l-4 border-l-slate-300 border-slate-200 bg-slate-50'
                }`}
              >
                <div className="flex items-center justify-between w-full sm:w-auto gap-3 shrink-0">
                  {/* Milestone-style Index Box */}
                  <div
                    className={`w-8 h-8 sm:w-9 sm:h-9 rounded flex items-center justify-center font-mono font-bold text-xs shrink-0 border ${
                      hasResult
                        ? passed
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                          : 'bg-rose-100 text-rose-800 border-rose-300'
                        : 'bg-white text-slate-600 border-slate-200'
                    }`}
                  >
                    T{index + 1}
                  </div>

                  {/* Outcome badge on mobile top right */}
                  <div className="sm:hidden text-right">
                    {hasResult ? (
                      <div className="flex items-center gap-2">
                        {passed ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-300 text-[10px] font-bold uppercase">
                            <CheckCircle2 className="h-3 w-3" />
                            <span>PASS</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300 text-[10px] font-bold uppercase">
                            <XCircle className="h-3 w-3" />
                            <span>FAIL</span>
                          </span>
                        )}
                        <span className="text-[10px] font-mono text-slate-500 font-semibold">
                          {test.lastResult?.score}/100
                        </span>
                      </div>
                    ) : (
                      <span className="text-[10px] font-semibold uppercase px-2 py-0.5 bg-white rounded border border-slate-200 text-slate-500">
                        Pending
                      </span>
                    )}
                  </div>
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0 space-y-1 w-full">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold text-xs text-slate-900">{test.name}</span>
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded uppercase ${
                        test.category === 'SAFE'
                          ? 'bg-emerald-100 text-emerald-800'
                          : test.category === 'OBVIOUS_INJECTION'
                          ? 'bg-rose-100 text-rose-800'
                          : test.category === 'ENCODED'
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-purple-100 text-purple-800'
                      }`}
                    >
                      {test.category}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono font-semibold">
                      Target: {test.expectedAction}
                    </span>
                  </div>

                  <p className="text-xs font-mono text-slate-700 bg-white p-2 rounded border border-slate-200/80 truncate">
                    "{test.prompt}"
                  </p>
                  <p className="text-[11px] text-slate-500">{test.description}</p>
                </div>

                {/* Outcome badge on desktop */}
                <div className="hidden sm:block shrink-0 text-right">
                  {hasResult ? (
                    <div className="space-y-1">
                      {passed ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-300 text-[10px] font-bold uppercase">
                          <CheckCircle2 className="h-3 w-3" />
                          <span>PASS</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300 text-[10px] font-bold uppercase">
                          <XCircle className="h-3 w-3" />
                          <span>FAIL</span>
                        </span>
                      )}
                      <div className="text-[10px] font-mono text-slate-500 font-semibold">
                        Score: {test.lastResult?.score}/100 ({test.lastResult?.latencyMs}ms)
                      </div>
                    </div>
                  ) : (
                    <span className="text-[10px] font-semibold uppercase px-2 py-0.5 bg-white rounded border border-slate-200 text-slate-500">
                      Pending
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
