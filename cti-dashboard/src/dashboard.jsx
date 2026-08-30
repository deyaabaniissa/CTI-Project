import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Calendar,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Cpu,
  Database,
  Download,
  Eye,
  FileText,
  Fingerprint,
  Globe2,
  Hospital,
  LogOut,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Signal,
  Trash2,
  WifiOff,
  X,
} from 'lucide-react';
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import './dashboard.css';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';
const WS_URL =
  import.meta.env.VITE_WS_URL ||
  `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/live-logs`;
// Bump when the report schema changes so stale per-row Log4Shell evidence is
// not restored from a browser that visited an older build.
const LOG_STORAGE_KEY = 'healthcare_soc_logs_v13';
const MAX_LOGS = 400;
const EVALUATION_PAGE_SIZE = 25;
const REPLAY_BATCH_SIZE = 1;
const REPLAY_INTERVAL_MS = 2000;
const PROVIDER_ORDER = ['otx', 'virustotal', 'osv', 'nvd'];
const PROVIDER_NAMES = {
  otx: 'AlienVault OTX',
  virustotal: 'VirusTotal',
  osv: 'OSV',
  nvd: 'NIST NVD',
};
const CATEGORY_META = {
  'IoMT network flows': { label: 'IoMT network flows', icon: Radio, color: '#61b4d8' },
};

const TLP_META = {
  'TLP:RED': { label: 'TLP:RED', color: '#e85d75', tone: 'red' },
  'TLP:AMBER': { label: 'TLP:AMBER', color: '#e6a23c', tone: 'amber' },
  'TLP:GREEN': { label: 'TLP:GREEN', color: '#3ab795', tone: 'green' },
  'TLP:CLEAR': { label: 'TLP:CLEAR', color: '#92a4b7', tone: 'clear' },
};

const FAMILY_COLORS = {
  Benign: '#3ab795',
  DDoS: '#e85d75',
  DoS: '#f28c6f',
  MQTT: '#61b4d8',
  Recon: '#d7b46a',
  Spoofing: '#9d83d5',
  Unknown: '#92a4b7',
};

const DEFAULT_FILTERS = {
  category: 'ALL',
  tlp: 'ALL',
  date: '',
  timeFrom: '',
  timeTo: '',
  query: '',
};

const loadSavedLogs = () => {
  try {
    const saved = localStorage.getItem(LOG_STORAGE_KEY);
    return saved ? JSON.parse(saved) : [];
  } catch {
    return [];
  }
};

const toFiniteNumber = (value, fallback = 0) => {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
};

const normalizeLog = (log) => {
  const severity = String(log.severity || log.risk_level || 'low').toLowerCase();
  const sharingClassification = String(log.sharing_classification || log.tlp || 'TLP:CLEAR');
  const logId = String(log.log_id || `LOG-${Date.now()}`);
  const evaluationMode = Boolean(
    log.evaluation_mode
    || log.report_type === 'held_out_model_evaluation'
    || logId.startsWith('CIC24-TEST-'),
  );
  const liveEvidenceEndpoint = log.live_evidence_endpoint || (
    evaluationMode
      ? `/api/evaluation-samples/${encodeURIComponent(logId)}/live-evidence`
      : log.investigation_id
        ? `/api/investigations/${encodeURIComponent(log.investigation_id)}/live-evidence`
        : null
  );
  return {
    ...log,
    log_id: logId,
    evaluation_mode: evaluationMode,
    live_evidence_endpoint: liveEvidenceEndpoint,
    category: 'IoMT network flows',
    department: String(log.department || 'General'),
    destination_target: String(log.destination_target || '0.0.0.0'),
    source_ip: String(log.source_ip || '0.0.0.0'),
    data_mb: toFiniteNumber(log.data_mb),
    is_threat: toFiniteNumber(log.is_threat),
    is_in_otx: Boolean(log.is_in_otx),
    risk_level: severity,
    severity,
    risk_probability: toFiniteNumber(
      log.risk_adjustment_applied && log.live_fused_risk != null
        ? toFiniteNumber(log.live_fused_risk) / 100
        : (log.risk_probability ?? log.attack_probability),
    ),
    attack_probability: toFiniteNumber(log.attack_probability ?? log.risk_probability),
    model_probability: toFiniteNumber(log.predicted_class_confidence ?? log.model_probability),
    predicted_class_confidence: toFiniteNumber(log.predicted_class_confidence ?? log.model_probability),
    features: log.features || log.model_details?.features || {},
    class_probabilities: log.class_probabilities || log.model_details?.probabilities || {},
    intel_verdict: String(log.intel_verdict || 'unknown'),
    tlp: sharingClassification,
    sharing_classification: sharingClassification,
    timestamp: String(log.timestamp || new Date().toLocaleTimeString('en-GB')),
    date: String(log.date || new Date().toISOString().slice(0, 10)),
  };
};

const mergeLogWindow = (primary, secondary = []) => {
  const seen = new Set();
  return [...primary, ...secondary]
    .map(normalizeLog)
    .filter((log) => {
      const identity = String(log.investigation_id || log.log_id);
      if (seen.has(identity)) {
        return false;
      }
      seen.add(identity);
      return true;
    })
    .slice(0, MAX_LOGS);
};

const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

const exportCsv = (logs) => {
  const columns = [
    'log_id',
    'date',
    'timestamp',
    'category',
    'department',
    'source_ip',
    'destination_target',
    'data_mb',
    'is_in_otx',
    'tlp',
  ];
  const rows = logs.map((log) =>
    columns
      .map((column) => `"${String(log[column] ?? '').replace(/"/g, '""')}"`)
      .join(','),
  );
  const blob = new Blob([[columns.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `healthcare-soc-logs-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
};

const formatReportLabel = (key) =>
  ({
    attack_probability: 'Attack Probability P(non-Benign)',
    predicted_class_confidence: 'Predicted-Class Confidence',
    sharing_classification: 'Sharing Classification',
    original_event_time: 'Original Event Time',
    replay_time: 'Replay Time',
  }[key] || key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace(/\bIp\b/g, 'IP')
    .replace(/\bOtx\b/g, 'OTX')
    .replace(/\bTlp\b/g, 'TLP'));

const getLogThreatStatus = (log) => {
  const predictedThreat = String(log.traffic_class || '') !== 'Benign';
  if (log.evaluation_mode) {
    const correctness = log.prediction_correct ? 'Correct' : 'Incorrect';
    return `Predicted ${predictedThreat ? 'Threat' : 'Safe'} — ${correctness}`;
  }
  return log.is_threat === 1 ? 'Threat' : 'Safe';
};

const getReportTypeLabel = (log) => (
  log.report_type_label || (
    log.evaluation_mode ? 'Held-out model evaluation' : 'Live incident investigation'
  )
);

const getModelScoreLabel = (log) => (
  `${formatReportLabel(log.severity || 'low')} model score`
);

const getReportSummary = (log) => {
  if (log.evaluation_mode) {
    return [
      ['Report type', getReportTypeLabel(log)],
      ['Prediction outcome', getLogThreatStatus(log)],
      ['Model score level', getModelScoreLabel(log)],
      ['Evaluation time', getReportTimeValue(log)],
    ];
  }
  return [
    ['Report type', getReportTypeLabel(log)],
    ['Fused verdict', getLogThreatStatus(log)],
    ['Incident risk', SEVERITY_META[log.severity]?.label || formatReportLabel(log.severity)],
    ['Observed time', getReportTimeValue(log)],
  ];
};

const getEvidenceMethodNote = (log) => {
  if (!log.evaluation_mode) {
    return 'Providers are queried only when this log contains a compatible indicator: OTX and VirusTotal for IP/domain/URL/hash values; OSV and NVD for CVE or vulnerability references.';
  }
  if (log.evidence_mode === 'capture_and_dependency_context') {
    return 'OTX and VirusTotal query public indicators extracted from the official PCAP capture. OSV queries an exact package version from the deployed project dependency files, and NVD queries only CVE aliases returned by OSV. These are two clearly separated context planes; neither is presented as a native field of this numeric TEST row.';
  }
  if (log.evidence_mode === 'capture_context') {
    return 'AlienVault OTX and VirusTotal results use public IoCs read from pcap_api_ready_indicators.csv. They are capture-level context, not fields stored in this exact numeric TEST row.';
  }
  if (log.evidence_mode === 'pending_context') {
    return 'Live contextual enrichment is loading: OTX/VirusTotal will inspect official PCAP indicators, while OSV/NVD will inspect exact deployed dependency versions.';
  }
  return 'This held-out model row contains numeric flow features only. The statuses below verify that each API is reachable; no provider finding is attributed to this row because it has no IP, domain, URL, hash, CVE, or package identifier.';
};

const getEvidenceHeading = (log) => (
  log.evaluation_mode && ['capture_and_dependency_context', 'capture_context'].includes(log.evidence_mode)
    ? 'Context-Only Threat Intelligence'
    : 'Threat-Intelligence Evidence'
);

const getReportTimeLabel = (log) => (log.evaluation_mode ? 'Replay Time' : 'Observed Time');

const getReportTimeValue = (log) => (
  log.evaluation_mode
    ? String(log.replay_time || `${log.date} ${log.timestamp}`)
    : String(log.observed_time || `${log.date} ${log.timestamp}`)
);

const getProviderRows = (log) => {
  const supplied = new Map(
    (Array.isArray(log.provider_evidence) ? log.provider_evidence : []).map((item) => [item.provider_id, item]),
  );
  return PROVIDER_ORDER.map((providerId) => supplied.get(providerId) || {
    provider_id: providerId,
    provider: PROVIDER_NAMES[providerId],
    configured: false,
    applicable: false,
    queried: false,
    available: false,
    status: 'not_recorded',
    result: 'No per-event provider result is attached to this legacy log.',
  });
};

const providerStatusLabel = (provider) => {
  if (provider.status === 'available' && provider.context_only && provider.lookup_mode === 'live_api') {
    return 'Live API — contextual evidence only';
  }
  if (provider.status === 'available' && provider.context_only) return 'Queried — contextual evidence only';
  if (provider.status === 'available' && provider.lookup_mode === 'live_api') return 'Live API — connected';
  if (provider.status === 'available' && provider.lookup_mode === 'saved_cache') return 'Cached result — not live';
  if (provider.status === 'available') return 'Queried — available';
  if (provider.status === 'not_applicable' && provider.connection_status === 'live') {
    return 'Live API connected — no log indicator';
  }
  if (provider.status === 'not_applicable' && provider.connection_status === 'error') {
    return 'API connection error — no log indicator';
  }
  if (provider.status === 'not_applicable' && provider.connection_status === 'ready') {
    return 'API configured — no log indicator';
  }
  if (provider.status === 'not_applicable') return 'Not applicable to this log';
  if (provider.status === 'not_configured') return 'Applicable — not configured';
  if (provider.status === 'not_queried') return 'Applicable — not queried';
  if (provider.status === 'unavailable') {
    const failed = (provider.observations || []).find((observation) => observation.verdict === 'error');
    const httpStatus = failed?.metrics?.http_status;
    const errorType = String(failed?.metrics?.error_type || '').replace(/_/g, ' ');
    if (httpStatus) return `Lookup failed — HTTP ${httpStatus}`;
    return errorType ? `Lookup failed — ${errorType}` : 'Lookup failed — see details';
  }
  return 'Not recorded';
};

const SEVERITY_META = {
  critical: { label: 'Critical severity', color: '#e85d75', tone: 'critical' },
  high: { label: 'High severity', color: '#f28c6f', tone: 'high' },
  medium: { label: 'Medium severity', color: '#e6a23c', tone: 'medium' },
  low: { label: 'Low severity', color: '#3ab795', tone: 'low' },
};

const attachProviderConnections = (log, sourceStates = {}, checkedAt = null) => ({
  ...log,
  provider_evidence: getProviderRows(log).map((provider) => {
    const state = sourceStates[provider.provider_id] || {};
    return {
      ...provider,
      connection_status: state.status || provider.connection_status || 'unknown',
      connection_verified_at: state.last_success || checkedAt || provider.connection_verified_at || null,
      connection_error: state.last_error || null,
    };
  }),
});

const PROVIDER_VERDICTS = {
  malicious: { label: 'Malicious', tone: 'danger' },
  vulnerable: { label: 'Vulnerability confirmed', tone: 'danger' },
  suspicious: { label: 'Suspicious', tone: 'warning' },
  match: { label: 'Threat-intelligence match', tone: 'warning' },
  clean: { label: 'No reputation finding', tone: 'safe' },
  no_match: { label: 'No reputation finding', tone: 'safe' },
  not_found: { label: 'No reputation finding', tone: 'safe' },
  error: { label: 'Lookup error', tone: 'muted' },
};

const providerObservationView = (providerId, observation) => {
  const metrics = observation.metrics || {};
  const contextOnly = observation.attributable_to_log === false;
  let verdict = PROVIDER_VERDICTS[observation.verdict] || {
    label: formatReportLabel(observation.verdict || 'unknown'),
    tone: 'muted',
  };
  let summary = observation.result || 'No finding details were returned.';
  let facts = [];

  if (observation.verdict === 'error') {
    return {
      verdict,
      summary,
      facts: [
        ['Error type', String(metrics.error_type || 'provider error').replace(/_/g, ' ')],
        ['HTTP status', metrics.http_status || 'Not available'],
      ],
    };
  }

  if (providerId === 'otx') {
    const pulses = toFiniteNumber(metrics.pulse_count);
    summary = pulses
      ? `This indicator appears in ${pulses} AlienVault community threat pulse${pulses === 1 ? '' : 's'}.`
      : 'AlienVault OTX did not associate this indicator with a community threat pulse.';
    facts = [
      ['OTX pulses', pulses],
      ['Reputation score', toFiniteNumber(metrics.reputation)],
      ['Validation records', toFiniteNumber(metrics.validation_count)],
    ];
  } else if (providerId === 'virustotal') {
    const malicious = toFiniteNumber(metrics.malicious);
    const suspicious = toFiniteNumber(metrics.suspicious);
    const harmless = toFiniteNumber(metrics.harmless);
    const total = toFiniteNumber(metrics.total_engines);
    const detectionRate = total ? `${((malicious / total) * 100).toFixed(1)}%` : '0.0%';
    summary = malicious
      ? `${malicious} of ${total} security engines classified this indicator as malicious (${detectionRate}).`
      : suspicious
        ? `${suspicious} security engine${suspicious === 1 ? '' : 's'} marked this indicator as suspicious.`
        : `No malicious engine detections were returned out of ${total} checked engines.`;
    facts = [
      ['Malicious', malicious],
      ['Suspicious', suspicious],
      ['Harmless', harmless],
      ['Engines checked', total],
    ];
  } else if (providerId === 'osv') {
    const affected = toFiniteNumber(metrics.affected_packages);
    summary = metrics.found
      ? `OSV confirmed the vulnerability and returned ${affected} affected package record${affected === 1 ? '' : 's'}.`
      : 'OSV did not return a vulnerability record for this identifier.';
    facts = [
      ['Advisory', metrics.id || observation.indicator],
      ['Affected packages', affected],
    ];
  } else if (providerId === 'nvd') {
    const severity = Array.isArray(metrics.severities) && metrics.severities.length
      ? metrics.severities.join(', ')
      : 'Not reported';
    const cvss = toFiniteNumber(metrics.max_cvss).toFixed(1);
    summary = metrics.found
      ? `NVD confirmed the CVE with ${severity} severity and a maximum CVSS score of ${cvss}/10.`
      : 'NVD did not return a matching CVE record.';
    facts = [
      ['CVE', (metrics.cve_ids || []).join(', ') || observation.indicator],
      ['Severity', severity],
      ['Maximum CVSS', `${cvss}/10`],
      ['Known exploited', metrics.known_exploited ? 'Yes' : 'No'],
    ];
  }

  if (contextOnly) {
    const platformContext = providerId === 'osv' || providerId === 'nvd';
    const noReputationFinding = ['clean', 'no_match', 'not_found'].includes(observation.verdict);
    verdict = {
      label: platformContext
        ? 'Platform finding — not this log'
        : noReputationFinding
          ? 'No reputation finding — context only'
          : 'Capture finding — not this log',
      tone: 'muted',
    };
    summary = `${platformContext ? 'Platform context only' : 'Capture context only'}: ${summary} `
      + 'This finding is not attributable to the current CICIoMT2024 flow row and does not change its model prediction or risk.';
    facts.push(['Evidence scope', platformContext ? 'Deployed platform dependency' : 'Official PCAP capture']);
    facts.push(['Attributed to this log', 'No']);
  }

  return { verdict, summary, facts };
};

const buildProviderResultHtml = (provider) => {
  const observations = (Array.isArray(provider.observations) ? provider.observations : [])
    .filter((observation) => observation?.indicator && observation?.metrics);
  if (!observations.length) return `<p class="provider-fallback">${escapeHtml(provider.result)}</p>`;
  return observations.map((observation) => {
    const view = providerObservationView(provider.provider_id, observation);
    const facts = view.facts
      .map(([label, value]) => `<span><b>${escapeHtml(label)}</b>${escapeHtml(value)}</span>`)
      .join('');
    return `<div class="provider-observation">
      <div class="provider-observation-head">
        <strong>${escapeHtml(observation.indicator)}</strong>
        <em class="verdict-pill ${escapeHtml(view.verdict.tone)}">${escapeHtml(view.verdict.label)}</em>
      </div>
      <p>${escapeHtml(view.summary)}</p>
      <div class="provider-facts">${facts}</div>
    </div>`;
  }).join('');
};

const getReportRows = (log) => {
  const empty = 'Not applicable / not supplied';
  const probability = `${(toFiniteNumber(log.attack_probability) * 100).toFixed(2)}%`;
  const liveFusedRisk = `${toFiniteNumber(log.live_fused_risk).toFixed(2)}%`;
  const confidence = `${(toFiniteNumber(log.predicted_class_confidence) * 100).toFixed(2)}%`;
  const predictionOutcome = log.evaluation_mode
    ? (log.prediction_correct ? 'Correct' : 'Incorrect')
    : 'Ground truth is not available for a live event';
  return [
    ['Report ID', log.log_id],
    ['Report Type', getReportTypeLabel(log)],
    ['Category', log.category],
    ['Model Prediction', log.traffic_class || empty],
    ['Ground Truth', log.evaluation_mode ? (log.true_family || empty) : empty],
    ['Prediction Outcome', predictionOutcome],
    ['Operational Context', log.department || empty],
    ['Source IP', log.source_ip || empty],
    ['Destination Target', log.destination_target || empty],
    ['Data Volume', `${toFiniteNumber(log.data_mb)} ${log.data_unit || 'KB'}`],
    ['Model Risk P(non-Benign)', probability],
    ...(log.live_evidence_checked_at && log.risk_adjustment_applied
      ? [
          ['Live Fused Risk', liveFusedRisk],
          ['Live CTI Adjustment', 'Applied — attributable live indicators changed the operational risk.'],
        ]
      : []),
    ...(log.live_evidence_checked_at && !log.risk_adjustment_applied
      ? [[
          'CTI Risk Adjustment',
          'Not applicable — the API findings are contextual and are not indicators from this TEST row.',
        ]]
      : []),
    ['Predicted-Class Confidence', confidence],
    ['CTI Verdict', log.intel_verdict || empty],
    ['Sharing Classification', log.sharing_classification || log.tlp || empty],
    ['Dataset', log.source_dataset || (log.evaluation_mode ? 'CICIoMT2024' : empty)],
    ['Dataset Split', log.source_split || (log.evaluation_mode ? 'Official TEST' : empty)],
    ['Source Record', log.source_row_number ?? empty],
    [getReportTimeLabel(log), getReportTimeValue(log)],
  ];
};

const getReportRecommendations = (log) => {
  if (Array.isArray(log.recommended_actions) && log.recommended_actions.length) {
    return log.recommended_actions.map((item) => ({
      priority: String(item.priority || 'Review'),
      action: String(item.action || ''),
      problem: String(item.problem || ''),
      evidenceSources: Array.isArray(item.evidence_sources) ? item.evidence_sources.map(String) : [],
      evidence: String(item.evidence || ''),
    }));
  }

  let fallback;
  if (log.severity === 'critical' || log.severity === 'high') {
    fallback = [
      'Escalate to the incident response owner immediately.',
      'Validate source and destination assets before allowing continued communication.',
      'Preserve related telemetry and attach this report to the incident record.',
    ];
  } else if (log.severity === 'medium' || log.is_threat === 1) {
    fallback = [
      'Review the event with the responsible department.',
      'Correlate with endpoint and firewall telemetry for the same time window.',
      'Keep sharing limited to the response team until the event is confirmed.',
    ];
  } else if (log.severity === 'low') {
    fallback = [
      'Monitor for repeated high-volume activity from the same assets.',
      'Share within trusted operational teams if needed for awareness.',
    ];
  } else {
    fallback = [
      'No immediate action required.',
      'Retain the report for audit history and baseline comparison.',
    ];
  }
  return fallback.map((action) => ({
    priority: 'Legacy guidance',
    action,
    problem: 'This saved log predates per-provider report evidence.',
    evidenceSources: ['Local dashboard policy'],
    evidence: 'Generate a new live log to obtain API-linked recommendations.',
  }));
};

const downloadTextFile = (filename, content, type = 'text/html;charset=utf-8') => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};

const buildReportHtml = (log) => {
  const tlpMeta = TLP_META[log.tlp] || TLP_META['TLP:CLEAR'];
  const severityMeta = SEVERITY_META[log.severity] || SEVERITY_META.low;
  const rows = getReportRows(log)
    .map(
      ([label, value]) =>
        `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value)}</td></tr>`,
    )
    .join('');
  const providerRows = getProviderRows(log)
    .map(
      (provider) => `<tr>
        <td>${escapeHtml(provider.provider)}</td>
        <td>${escapeHtml(providerStatusLabel(provider))}</td>
        <td>${buildProviderResultHtml(provider)}</td>
      </tr>`,
    )
    .join('');
  const recommendations = getReportRecommendations(log)
    .map((item) => `<li>
      <strong>[${escapeHtml(item.priority)}] ${escapeHtml(item.action)}</strong>
      <div><b>Problem addressed:</b> ${escapeHtml(item.problem)}</div>
      <div><b>Evidence:</b> ${escapeHtml(item.evidence)}</div>
      <div><b>Sources:</b> ${escapeHtml(item.evidenceSources.join(', ') || 'Local policy')}</div>
    </li>`)
    .join('');
  const reasons = (Array.isArray(log.risk_reasons) ? log.risk_reasons : [])
    .map((reason) => `<li>${escapeHtml(reason)}</li>`)
    .join('');
  const featureRows = Object.entries(log.features || {})
    .map(([feature, value]) => `<tr><th>${escapeHtml(feature)}</th><td>${escapeHtml(value)}</td></tr>`)
    .join('');
  const probabilityRows = Object.entries(log.class_probabilities || {})
    .map(([family, value]) => `<tr><th>${escapeHtml(family)}</th><td>${escapeHtml(`${(toFiniteNumber(value) * 100).toFixed(2)}%`)}</td></tr>`)
    .join('');
  const reportTitle = log.evaluation_mode ? 'Model Evaluation Report' : 'Security Analysis Report';
  const reportDescription = log.evaluation_mode
    ? 'Report type: held-out model evaluation. This is not a live incident verdict. Ground truth is available, and contextual CTI is not attributed to the numeric TEST row.'
    : 'Report type: live incident investigation. The model result is fused with evidence returned for indicators actually present in this event.';
  const summaryRows = getReportSummary(log)
    .map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`)
    .join('');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(reportTitle)} - ${escapeHtml(log.log_id)}</title>
    <style>
      body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; color: #16222c; background: #f4f7fa; }
      main { max-width: 920px; margin: 24px auto; padding: 34px; background: #fff; border: 1px solid #d8e1e8; }
      header { display: flex; justify-content: space-between; gap: 24px; border-bottom: 3px solid #167f92; padding-bottom: 18px; }
      h1, h2 { margin: 0; }
      h1 { font-size: 25px; }
      h2 { margin-top: 26px; font-size: 18px; }
      p { margin: 8px 0 0; color: #637485; }
      .badges { display: flex; align-items: flex-start; gap: 8px; flex-wrap: wrap; }
      .badge { border-radius: 6px; padding: 8px 12px; color: #fff; font-weight: 800; }
      .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: 12px; margin-top: 22px; }
      .summary div { padding: 12px; background: #f6f9fb; border: 1px solid #d8e1e8; border-radius: 6px; }
      .summary span { display: block; color: #637485; font-size: 12px; font-weight: 700; text-transform: uppercase; }
      .summary strong { display: block; margin-top: 5px; overflow-wrap: anywhere; }
      table { width: 100%; border-collapse: collapse; margin-top: 14px; }
      th, td { border: 1px solid #d8e1e8; padding: 10px 12px; text-align: left; vertical-align: top; }
      th { width: 34%; background: #f6f9fb; }
      td { overflow-wrap: anywhere; }
      li { margin: 8px 0; }
      .provider-table th { width: auto; }
      .provider-table td:first-child { width: 20%; font-weight: 700; }
      .provider-table td:nth-child(2) { width: 22%; }
      .provider-observation + .provider-observation { margin-top: 12px; padding-top: 12px; border-top: 1px solid #d8e1e8; }
      .provider-observation-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
      .provider-observation-head strong { overflow-wrap: anywhere; }
      .provider-observation p, .provider-fallback { margin: 7px 0; color: #314555; }
      .verdict-pill { flex: none; padding: 3px 7px; border-radius: 999px; font-size: 11px; font-style: normal; font-weight: 800; }
      .verdict-pill.danger { color: #9b1730; background: #fde8ed; }
      .verdict-pill.warning { color: #7c5100; background: #fff1cf; }
      .verdict-pill.safe { color: #12634f; background: #dcf7ef; }
      .verdict-pill.muted { color: #526474; background: #e9eef2; }
      .provider-facts { display: flex; flex-wrap: wrap; gap: 6px; }
      .provider-facts span { padding: 5px 7px; border-radius: 4px; background: #f1f5f8; font-size: 11px; }
      .provider-facts b { margin-right: 4px; }
      .recommendations li { margin-bottom: 14px; }
      .recommendations div { margin-top: 4px; }
      .method-note { padding: 10px 12px; background: #f6f9fb; border-left: 3px solid #167f92; }
    </style>
  </head>
  <body>
    <main>
      <header>
        <div>
          <h1>Healthcare CTI SOC ${escapeHtml(reportTitle)}</h1>
          <p>${escapeHtml(reportDescription)}</p>
        </div>
        <div class="badges">
          <span class="badge" style="background:${severityMeta.color}">${escapeHtml(log.evaluation_mode ? getModelScoreLabel(log) : severityMeta.label)}</span>
          <span class="badge" style="background:${tlpMeta.color}">${escapeHtml(log.sharing_classification || log.tlp)}</span>
        </div>
      </header>
      <section class="summary" aria-label="Report summary">${summaryRows}</section>
      <h2>Log Details</h2>
      <table><tbody>${rows}</tbody></table>
      ${featureRows ? `<h2>12 Model Features</h2><table><tbody>${featureRows}</tbody></table>` : ''}
      ${probabilityRows ? `<h2>Class Probabilities</h2><table><tbody>${probabilityRows}</tbody></table>` : ''}
      <h2>${escapeHtml(getEvidenceHeading(log))}</h2>
      <p>${escapeHtml(getEvidenceMethodNote(log))}</p>
      <table class="provider-table">
        <thead><tr><th>Provider</th><th>Provider status</th><th>Evidence result</th></tr></thead>
        <tbody>${providerRows}</tbody>
      </table>
      ${reasons ? `<h2>Decision Reasons</h2><ul>${reasons}</ul>` : ''}
      <h2>Evidence-Linked Recommended Actions</h2>
      <p class="method-note">${escapeHtml(log.recommendation_method || 'Recommendations are local policy guidance; verify before operational action.')}</p>
      <ul class="recommendations">${recommendations}</ul>
    </main>
  </body>
</html>`;
};

const installReport = async (log, reportElement) => {
  const filename = `healthcare-soc-report-${log.log_id}.pdf`;

  try {
    const html2pdf = (await import('html2pdf.js')).default;
    await html2pdf()
      .set({
        margin: 0.35,
        filename,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true },
        jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' },
      })
      .from(reportElement)
      .save();
  } catch {
    downloadTextFile(`healthcare-soc-report-${log.log_id}.html`, buildReportHtml(log));
  }
};

export default function Dashboard({ onLogout }) {
  const [persistedLogs, setPersistedLogs] = useState(loadSavedLogs);
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [lastSeen, setLastSeen] = useState(null);
  const [selectedReportLog, setSelectedReportLog] = useState(null);
  const [liveEvidenceLoading, setLiveEvidenceLoading] = useState(false);
  const [liveEvidenceMessage, setLiveEvidenceMessage] = useState('');
  const [sourceStatus, setSourceStatus] = useState({});
  const [analystAlerts, setAnalystAlerts] = useState([]);
  const [databaseStatus, setDatabaseStatus] = useState({
    status: 'pending',
    backend: 'loading',
    counts: {},
  });
  const [modelInfo, setModelInfo] = useState({
    model_name: 'CICIoMT2024 CatBoost',
    features: [],
    classes: [],
    metrics: {},
    feature_importance: [],
    training_dataset: {},
  });
  const [posture, setPosture] = useState({
    state: 'pending',
    packages_scanned: 0,
    vulnerability_count: 0,
    critical_count: 0,
    known_exploited_count: 0,
    max_cvss: 0,
  });
  const [intelligenceLoading, setIntelligenceLoading] = useState(false);
  const [integrationLoading, setIntegrationLoading] = useState(false);
  const [integrationMessage, setIntegrationMessage] = useState('');
  const [evaluationSamples, setEvaluationSamples] = useState([]);
  const [streamedEvaluationLogs, setStreamedEvaluationLogs] = useState([]);
  const [evaluationSummary, setEvaluationSummary] = useState({
    total: 0,
    correct: 0,
    incorrect: 0,
    accuracy: 0,
    rows_per_family: {},
  });
  const [evaluationLoading, setEvaluationLoading] = useState(true);
  const [evaluationError, setEvaluationError] = useState('');
  const [evaluationFamily, setEvaluationFamily] = useState('ALL');
  const [evaluationResult, setEvaluationResult] = useState('ALL');
  const [evaluationQuery, setEvaluationQuery] = useState('');
  const [evaluationPage, setEvaluationPage] = useState(1);
  const reportRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const retryRef = useRef(0);

  useEffect(() => {
    let socket;
    let closedByUnmount = false;

    const connect = () => {
      setConnectionStatus('connecting');
      socket = new WebSocket(WS_URL);

      socket.onopen = () => {
        retryRef.current = 0;
        setConnectionStatus('live');
      };

      socket.onmessage = (event) => {
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch {
          setConnectionStatus('offline');
          return;
        }
        if (payload.type === 'heartbeat') {
          setLastSeen(new Date());
          return;
        }
        if (payload.error) {
          setConnectionStatus('offline');
          return;
        }
        const incomingLog = normalizeLog(payload);
        setLastSeen(new Date());
        setPersistedLogs((current) => {
          const updated = mergeLogWindow([incomingLog], current);
          localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(updated));
          return updated;
        });
      };

      socket.onerror = () => {
        setConnectionStatus('offline');
      };

      socket.onclose = () => {
        if (closedByUnmount) {
          return;
        }

        setConnectionStatus('offline');
        retryRef.current += 1;
        const delay = Math.min(12000, 1500 * retryRef.current);
        reconnectTimerRef.current = window.setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      closedByUnmount = true;
      window.clearTimeout(reconnectTimerRef.current);
      socket?.close();
    };
  }, []);

  const loadIntelligence = async (forceRefresh = false) => {
    setIntelligenceLoading(true);
    try {
      if (forceRefresh) {
        await fetch(`${API_BASE_URL}/api/vulnerabilities/refresh`, { method: 'POST' });
      }
      const [statusResponse, postureResponse, alertsResponse, databaseResponse, investigationsResponse, modelResponse, connectivityResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/api/intelligence/status`),
        fetch(`${API_BASE_URL}/api/vulnerabilities/posture`),
        fetch(`${API_BASE_URL}/api/alerts?limit=4`),
        fetch(`${API_BASE_URL}/api/database/status`),
        fetch(`${API_BASE_URL}/api/investigations?limit=${MAX_LOGS}`),
        fetch(`${API_BASE_URL}/api/model`),
        fetch(`${API_BASE_URL}/api/intelligence/connectivity-check`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ force_refresh: forceRefresh }),
        }),
      ]);
      if (statusResponse.ok) {
        const statusPayload = await statusResponse.json();
        setSourceStatus(statusPayload.sources || {});
      }
      if (postureResponse.ok) {
        setPosture(await postureResponse.json());
      }
      if (alertsResponse.ok) {
        const alertPayload = await alertsResponse.json();
        setAnalystAlerts(alertPayload.alerts || []);
      }
      if (databaseResponse.ok) {
        setDatabaseStatus(await databaseResponse.json());
      }
      if (investigationsResponse.ok) {
        const investigationPayload = await investigationsResponse.json();
        const persistedLogs = mergeLogWindow(investigationPayload.investigations || []);
        setPersistedLogs(persistedLogs);
        localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(persistedLogs));
      }
      if (modelResponse.ok) {
        setModelInfo(await modelResponse.json());
      }
      if (connectivityResponse.ok) {
        const connectivityPayload = await connectivityResponse.json();
        setSourceStatus(connectivityPayload.sources || {});
      }
    } catch {
      const offlineSource = { status: 'error' };
      setSourceStatus({
        osv: offlineSource,
        nvd: offlineSource,
        otx: offlineSource,
        virustotal: offlineSource,
      });
      setPosture((current) => ({ ...current, state: 'offline' }));
      setDatabaseStatus({ status: 'offline', backend: 'offline', counts: {} });
    } finally {
      setIntelligenceLoading(false);
    }
  };

  useEffect(() => {
    loadIntelligence();
    const intervalId = window.setInterval(() => loadIntelligence(), 30000);
    return () => window.clearInterval(intervalId);
  }, []);

  useEffect(() => {
    if (!evaluationSamples.length) return undefined;

    let cursor = 0;
    setStreamedEvaluationLogs([]);
    const replayTimer = window.setInterval(() => {
      const now = new Date();
      const batch = evaluationSamples.slice(cursor, cursor + REPLAY_BATCH_SIZE).map((sample, index) => ({
        ...sample,
        date: now.toISOString().slice(0, 10),
        timestamp: now.toLocaleTimeString('en-GB'),
        replay_time: now.toISOString(),
        replay_sequence: cursor + index + 1,
        replay_stream: true,
      }));
      cursor += batch.length;
      if (batch.length) {
        setStreamedEvaluationLogs((current) => mergeLogWindow([...batch].reverse(), current));
        setLastSeen(now);
      }
      if (cursor >= evaluationSamples.length) window.clearInterval(replayTimer);
    }, REPLAY_INTERVAL_MS);

    return () => window.clearInterval(replayTimer);
  }, [evaluationSamples]);

  const logs = useMemo(
    () => mergeLogWindow(streamedEvaluationLogs, persistedLogs),
    [persistedLogs, streamedEvaluationLogs],
  );

  const replayStats = useMemo(() => {
    const correct = streamedEvaluationLogs.filter((sample) => sample.prediction_correct).length;
    const total = streamedEvaluationLogs.length;
    return {
      total,
      correct,
      incorrect: total - correct,
      accuracy: total ? correct / total : 0,
    };
  }, [streamedEvaluationLogs]);

  useEffect(() => {
    let active = true;
    const loadEvaluationSamples = async () => {
      setEvaluationLoading(true);
      setEvaluationError('');
      try {
        const response = await fetch(`${API_BASE_URL}/api/evaluation-samples`);
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error || payload.detail || 'Unable to load official TEST samples.');
        }
        if (active) {
          setEvaluationSamples((payload.samples || []).map(normalizeLog));
          setEvaluationSummary(payload.summary || {});
        }
      } catch (error) {
        if (active) setEvaluationError(error.message || 'Unable to load official TEST samples.');
      } finally {
        if (active) setEvaluationLoading(false);
      }
    };
    loadEvaluationSamples();
    return () => {
      active = false;
    };
  }, []);

  const stats = useMemo(() => {
    const totals = logs.reduce(
      (acc, log) => {
        const isThreat = log.evaluation_mode
          ? log.traffic_class !== 'Benign'
          : log.is_threat === 1;
        acc.total += 1;
        acc.threats += isThreat ? 1 : 0;
        acc.safe += isThreat ? 0 : 1;
        acc.otxMatches += log.is_in_otx ? 1 : 0;
        const family = String(log.traffic_class || 'Unknown');
        acc.families[family] = (acc.families[family] || 0) + 1;
        acc.categories[log.category] = (acc.categories[log.category] || 0) + 1;
        acc.tlp[log.tlp] = (acc.tlp[log.tlp] || 0) + 1;
        return acc;
      },
      {
        total: 0,
        threats: 0,
        safe: 0,
        otxMatches: 0,
        categories: {},
        tlp: {},
        families: {},
      },
    );

    return {
      ...totals,
      riskScore: totals.total ? Math.round((totals.threats / totals.total) * 100) : 0,
    };
  }, [logs]);

  const familyData = useMemo(
    () =>
      Object.entries(stats.families)
        .map(([name, value]) => ({ name, value, color: FAMILY_COLORS[name] || FAMILY_COLORS.Unknown }))
        .sort((a, b) => b.value - a.value),
    [stats.families],
  );

  const modelMetrics = modelInfo.metrics || {};
  const importanceByFeature = new Map(
    (modelInfo.feature_importance || []).map((item) => [item.feature, item]),
  );
  const featureImportance = (modelInfo.features || []).map((feature) => (
    importanceByFeature.get(feature) || { feature, importance: 0 }
  )).sort((left, right) => right.importance - left.importance);
  const maxFeatureImportance = featureImportance[0]?.importance || 1;
  const balanceData = modelInfo.training_dataset?.balance_audit || [];
  const maxBalanceRows = Math.max(
    1,
    ...balanceData.flatMap((item) => [Number(item.source_rows) || 0, Number(item.balanced_rows) || 0]),
  );
  const sourceTrainingRows = balanceData.reduce((total, item) => total + (Number(item.source_rows) || 0), 0);
  const balancedTrainingRows = balanceData.reduce((total, item) => total + (Number(item.balanced_rows) || 0), 0);
  const storedInvestigationCount = Number(databaseStatus.counts?.hospital_events || 0);
  const storedEvaluationCount = Number(databaseStatus.counts?.model_evaluation_samples || evaluationSummary.total || 0);

  const filteredLogs = useMemo(() => {
    const query = filters.query.trim().toLowerCase();

    return logs.filter((log) => {
      const matchesCategory = filters.category === 'ALL' || log.category === filters.category;
      const matchesTlp = filters.tlp === 'ALL' || log.tlp === filters.tlp;
      const matchesDate = !filters.date || log.date === filters.date;
      const matchesFrom = !filters.timeFrom || log.timestamp >= filters.timeFrom;
      const matchesTo = !filters.timeTo || log.timestamp <= filters.timeTo;
      const searchable = [
        log.log_id,
        log.category,
        log.department,
        log.source_ip,
        log.destination_target,
        log.tlp,
      ]
        .join(' ')
        .toLowerCase();
      const matchesQuery = !query || searchable.includes(query);

      return matchesCategory && matchesTlp && matchesDate && matchesFrom && matchesTo && matchesQuery;
    });
  }, [filters, logs]);

  const filteredEvaluationSamples = useMemo(() => {
    const query = evaluationQuery.trim().toLowerCase();
    return evaluationSamples.filter((sample) => {
      const familyMatches = evaluationFamily === 'ALL' || sample.true_family === evaluationFamily;
      const resultMatches =
        evaluationResult === 'ALL' ||
        (evaluationResult === 'CORRECT' && sample.prediction_correct) ||
        (evaluationResult === 'INCORRECT' && !sample.prediction_correct);
      const text = [
        sample.log_id,
        sample.true_family,
        sample.traffic_class,
        sample.attack_subclass,
        sample.destination_target,
      ].join(' ').toLowerCase();
      return familyMatches && resultMatches && (!query || text.includes(query));
    });
  }, [evaluationSamples, evaluationFamily, evaluationResult, evaluationQuery]);

  const evaluationPageCount = Math.max(1, Math.ceil(filteredEvaluationSamples.length / EVALUATION_PAGE_SIZE));
  const visibleEvaluationSamples = filteredEvaluationSamples.slice(
    (evaluationPage - 1) * EVALUATION_PAGE_SIZE,
    evaluationPage * EVALUATION_PAGE_SIZE,
  );

  useEffect(() => {
    setEvaluationPage(1);
  }, [evaluationFamily, evaluationResult, evaluationQuery]);

  useEffect(() => {
    if (evaluationPage > evaluationPageCount) setEvaluationPage(evaluationPageCount);
  }, [evaluationPage, evaluationPageCount]);

  const categoryData = Object.entries(CATEGORY_META).map(([key, meta]) => ({
    key,
    ...meta,
    count: stats.categories[key] || 0,
  }));

  const connectionMeta = {
    live: { label: 'Live event stream', icon: Signal },
    connecting: { label: 'Connecting stream', icon: Radio },
    offline: { label: 'Stream reconnecting', icon: WifiOff },
  }[connectionStatus];

  const updateFilter = (key, value) => {
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const clearLogs = () => {
    if (!window.confirm('Clear local dashboard history?')) {
      return;
    }

    localStorage.removeItem(LOG_STORAGE_KEY);
    setPersistedLogs([]);
    setStreamedEvaluationLogs([]);
  };

  const resetFilters = () => {
    setFilters(DEFAULT_FILTERS);
  };

  const handlePreviewReport = (log) => {
    const connectedLog = attachProviderConnections(log, sourceStatus);
    const freshReportLog = connectedLog.live_evidence_endpoint
      ? normalizeLog(attachProviderConnections({
          ...log,
          provider_evidence: [],
          indicator_evidence: [],
          evidence_mode: 'pending_live',
          live_evidence_checked_at: null,
        }, sourceStatus))
      : connectedLog;
    setSelectedReportLog(freshReportLog);
    setLiveEvidenceMessage(
      freshReportLog.live_evidence_endpoint
        ? 'Running fresh live queries for this report. Saved API evidence is not being reused...'
        : 'This report has no live-evidence endpoint.',
    );
    if (freshReportLog.live_evidence_endpoint) {
      void refreshLiveEvidence(freshReportLog, true);
    }
  };

  const refreshLiveEvidence = async (log, forceRefresh = true) => {
    const endpoint = log?.live_evidence_endpoint || (
      log?.evaluation_mode && log?.log_id
        ? `/api/evaluation-samples/${encodeURIComponent(log.log_id)}/live-evidence`
        : null
    );
    if (!endpoint) {
      setLiveEvidenceMessage('This report has no live-evidence endpoint.');
      return;
    }
    setLiveEvidenceLoading(true);
    setLiveEvidenceMessage('Connecting to AlienVault OTX, VirusTotal, OSV, and NIST NVD...');
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force_refresh: true }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || payload.detail || 'Live API refresh failed.');

      const updated = normalizeLog({
        ...log,
        provider_evidence: payload.provider_evidence,
        indicator_evidence: payload.indicator_evidence,
        evidence_mode: payload.evidence_mode || 'connectivity_only',
        live_evidence_checked_at: payload.checked_at,
        live_fused_risk: toFiniteNumber(payload.live_fused_risk),
        live_cti_score: toFiniteNumber(payload.live_cti_score),
        risk_adjustment_applied: Boolean(payload.risk_adjustment_applied),
        ...(payload.risk_adjustment_applied
          ? {
              risk_score: toFiniteNumber(payload.live_fused_risk),
              risk_probability: toFiniteNumber(payload.live_fused_risk) / 100,
              risk_level: String(payload.live_risk_level || log.risk_level || 'low').toLowerCase(),
              severity: String(payload.live_risk_level || log.severity || 'low').toLowerCase(),
            }
          : {}),
        risk_reasons: [
          ...(Array.isArray(log.risk_reasons)
            ? log.risk_reasons.filter((reason) => {
                const text = String(reason);
                return !text.startsWith('Attack probability P(non-Benign):')
                  && !text.startsWith('CatBoost attack probability P(non-Benign):')
                  && !text.startsWith('Live fused risk:')
                  && !text.startsWith('Live CTI returned context-only evidence');
              })
            : []),
          payload.live_risk_reason,
        ].filter(Boolean),
        intel_verdict: payload.evidence_mode === 'capture_and_dependency_context'
          ? 'Context only — PCAP and platform findings are not attributed to this TEST row'
          : payload.evidence_mode === 'capture_context'
            ? 'Context only — capture-level IoCs are not attributed to this TEST row'
          : payload.all_four_connected
            ? 'Not applicable — no row-level indicator was supplied'
            : 'API connectivity check completed with partial availability',
      });
      setSelectedReportLog(updated);
      setLiveEvidenceMessage(payload.message || (
        payload.all_four_connected
          ? 'Live connection verified for all four APIs.'
          : 'Live check completed. At least one provider is unavailable; see each provider row below.'
      ));
    } catch (error) {
      setLiveEvidenceMessage(error.message || 'Live API refresh failed.');
    } finally {
      setLiveEvidenceLoading(false);
    }
  };

  const handleInstallReport = async (log) => {
    if (selectedReportLog?.log_id === log.log_id && reportRef.current) {
      await installReport(log, reportRef.current);
      return;
    }

    const wrapper = document.createElement('div');
    wrapper.innerHTML = buildReportHtml(log);
    document.body.appendChild(wrapper);
    await installReport(log, wrapper.querySelector('main') || wrapper);
    wrapper.remove();
  };

  const runIntegrationSample = async () => {
    setIntegrationLoading(true);
    setIntegrationMessage('Running the external test fixture through CatBoost, then querying four CTI sources...');
    try {
      const response = await fetch(`${API_BASE_URL}/api/integration-sample/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || payload.detail || 'Integration test failed.');
      }
      const incomingLog = normalizeLog(payload.dashboard_log);
      setLastSeen(new Date());
      setPersistedLogs((current) => {
        const updated = [incomingLog, ...current].slice(0, MAX_LOGS);
        localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(updated));
        return updated;
      });
      setSelectedReportLog(incomingLog);
      setIntegrationMessage(
        `Complete and stored: ${payload.result.prediction.predicted_family} at ${(payload.result.prediction.confidence * 100).toFixed(1)}% confidence; risk ${payload.result.risk_score}/100.`,
      );
      await loadIntelligence();
    } catch (error) {
      setIntegrationMessage(error.message || 'Integration test failed.');
    } finally {
      setIntegrationLoading(false);
    }
  };

  const hasActiveFilters =
    filters.category !== 'ALL' ||
    filters.tlp !== 'ALL' ||
    Boolean(filters.date || filters.timeFrom || filters.timeTo || filters.query);
  const ConnectionIcon = connectionMeta.icon;

  return (
    <div className="soc-shell">
      <aside className="soc-sidebar" aria-label="SOC navigation">
        <div className="brand-block">
          <div className="brand-icon" aria-hidden="true">
            <Hospital size={28} />
          </div>
          <div>
            <span>Healthcare</span>
            <strong>CTI SOC</strong>
          </div>
        </div>

        <nav className="side-nav" aria-label="Dashboard sections">
          <a className="active" href="#overview">
            <Activity size={18} />
            Overview
          </a>
          <a href="#traffic">
            <Radio size={18} />
            Live Stream
          </a>
          <a href="#model-eda">
            <Cpu size={18} />
            Model & EDA
          </a>
          <a href="#intelligence">
            <Globe2 size={18} />
            Intelligence
          </a>
          <a href="#reports">
            <FileText size={18} />
            Reports
          </a>
        </nav>

        <div className="side-status">
          <span>Detection pipeline</span>
          <strong>Machine Learning IDS + 4 CTI APIs</strong>
          <p>CatBoost machine learning classifies 12 flow features. OSV, NVD, OTX, and VirusTotal then enrich matching indicators.</p>
        </div>
      </aside>

      <main className="soc-main">
        <section className="site-intro" aria-labelledby="platform-title">
          <div className="intro-copy">
            <p className="eyebrow">University Hospital Security Platform</p>
            <h1 id="platform-title">Healthcare Cyber Threat Intelligence SOC</h1>
            <p>
              Analyze IoMT network-flow events in one place. The platform uses a CatBoost machine-learning
              model to detect suspicious behavior, enriches supported indicators with live threat intelligence,
              and produces explainable alerts and incident-response recommendations.
            </p>
          </div>
          <div className="intro-capabilities" aria-label="Platform capabilities">
            <article>
              <Activity size={18} />
              <div><strong>Live posture</strong><span>Continuous event and alert monitoring</span></div>
            </article>
            <article>
              <ShieldCheck size={18} />
              <div><strong>TLP sharing</strong><span>Information-sharing classification, separate from severity</span></div>
            </article>
            <article>
              <Globe2 size={18} />
              <div><strong>Threat intelligence</strong><span>Indicator matching across four sources</span></div>
            </article>
            <article>
              <FileText size={18} />
              <div><strong>Incident reports</strong><span>Printable summaries for analyst triage</span></div>
            </article>
          </div>
        </section>

        <header className="topbar">
          <div>
            <p className="eyebrow">Live security operations</p>
            <h2>Operational dashboard</h2>
          </div>
          <div className="topbar-actions">
            <button
              className="integration-button"
              type="button"
              onClick={runIntegrationSample}
              disabled={integrationLoading}
              title="Run the bundled external test fixture through CatBoost, then enrich its indicators with OTX, VirusTotal, NVD, and OSV"
            >
              <Activity className={integrationLoading ? 'spin' : ''} size={17} />
              {integrationLoading ? 'Analyzing...' : 'Run model + 4 API test'}
            </button>
            <div className={`connection-pill ${connectionStatus}`}>
              <ConnectionIcon size={16} />
              <span>{connectionMeta.label}</span>
            </div>
            <button className="icon-button" type="button" onClick={() => exportCsv(filteredLogs)} title="Export filtered logs" aria-label="Export filtered logs">
              <Download size={18} />
            </button>
            <button className="icon-button danger" type="button" onClick={clearLogs} title="Clear local history" aria-label="Clear local history">
              <Trash2 size={18} />
            </button>
            <button className="logout-button" type="button" onClick={onLogout}>
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </header>

        {integrationMessage && (
          <div className={`integration-message ${integrationMessage.startsWith('Complete') ? 'success' : ''}`} role="status">
            {integrationMessage}
          </div>
        )}

        <section className="hero-band" id="overview">
          <div>
            <div className="hero-title-row">
              <span className="pulse-dot" aria-hidden="true" />
              <span>{lastSeen ? `Stream heartbeat ${lastSeen.toLocaleTimeString()}` : 'Waiting for event stream'}</span>
            </div>
            <h2>{stats.total} visible events: {stats.threats} threat predictions and {stats.safe} benign or safe predictions.</h2>
            <p>
              The held-out TEST stream adds one evaluated network-flow log every 2 seconds. {replayStats.total} of {evaluationSummary.total || 300} samples have entered the live window; persisted investigations remain stored separately.
            </p>
          </div>
          <div className="risk-meter" style={{ '--risk': stats.riskScore }} aria-label={`Risk score ${stats.riskScore} percent`}>
            <span>{stats.riskScore}</span>
            <small>% threat ratio</small>
          </div>
        </section>

        <section className="metric-grid" aria-label="Security metrics">
          <MetricCard icon={ShieldAlert} label="Threat Predictions" value={stats.threats} accent="#e85d75" helper="Current visible event window" />
          <MetricCard icon={ShieldCheck} label="Benign / Safe" value={stats.safe} accent="#3ab795" helper="Current visible event window" />
          <MetricCard icon={Signal} label="Stream Progress" value={`${replayStats.total}/${evaluationSummary.total || 300}`} accent="#61b4d8" helper="1 new log every 2 seconds" />
          <MetricCard icon={Database} label="Database Evaluation Rows" value={storedEvaluationCount} accent="#d7b46a" helper={`${storedInvestigationCount} persisted live investigations`} />
        </section>

        <section className="model-eda surface" id="model-eda" aria-label="Model validation and exploratory data analysis">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Model validation & EDA</p>
              <h2>CatBoost performance and feature interpretation</h2>
              <p className="section-description">Held-out CICIoMT2024 metrics for CatBoost gradient boosting: a machine-learning model, not a deep-learning neural network.</p>
            </div>
            <span className="model-badge">Machine Learning · CatBoost · {modelInfo.features?.length || 12} features</span>
          </div>
          <div className="eda-grid">
            <div className="validation-panel">
              <div className="validation-metrics">
                <ValidationMetric label="Accuracy" value={modelMetrics.accuracy} />
                <ValidationMetric label="Balanced accuracy" value={modelMetrics.balanced_accuracy} />
                <ValidationMetric label="Macro F1" value={modelMetrics.macro_f1} />
                <ValidationMetric label="Weighted F1" value={modelMetrics.weighted_f1} />
              </div>
              <div className="validation-audit-line">
                <ShieldCheck size={16} />
                <span>
                  Full scientific evaluation: <strong>{Number(modelInfo.evaluation?.official_test_rows || 47711).toLocaleString()}</strong> untouched Official TEST rows.
                  Evaluation replay: <strong>{Number(modelInfo.evaluation?.website_replay_rows || 300)}</strong> unique rows at <strong>{(toFiniteNumber(modelInfo.evaluation?.website_replay_accuracy || (278 / 300)) * 100).toFixed(1)}%</strong> accuracy. CTI is shown only for logs that include real indicators.
                </span>
              </div>
              <div className="pipeline-explainer">
                <div><span>1</span><strong>Detect</strong><p>CatBoost classifies 12 numeric flow features.</p></div>
                <div><span>2</span><strong>Enrich</strong><p>Four CTI APIs check relevant IoCs, CVEs, and packages.</p></div>
                <div><span>3</span><strong>Respond</strong><p>Risk fusion creates an alert and recommended actions.</p></div>
              </div>
            </div>
            <div className="feature-panel">
              <div className="panel-heading">
                <strong>All {featureImportance.length || 12} model features</strong>
                <span>Complete feature importance</span>
              </div>
              {featureImportance.map((item) => (
                <div className="feature-row" key={item.feature}>
                  <div><span>{item.feature}</span><em>{Number(item.importance).toFixed(1)}%</em></div>
                  <i style={{ width: `${Math.max(4, (item.importance / maxFeatureImportance) * 100)}%` }} />
                </div>
              ))}
            </div>
          </div>
        </section>

        {false && (
        <section className="evaluation-replay surface" id="test-replay" aria-label="CICIoMT2024 Official TEST replay">
          <div className="section-heading evaluation-heading">
            <div>
              <p className="eyebrow">Held-out model evaluation</p>
              <h2>300-sample Official TEST live replay</h2>
              <p className="section-description">
                Fifty unique rows from each of the six CICIoMT2024 families, sampled without replacement.
                These rows are used only for prediction and reporting—never for training, balancing, or tuning.
              </p>
            </div>
            <span className="model-badge">Live replay · 10 logs every 5 seconds</span>
          </div>

          <div className="evaluation-summary" aria-label="Replay summary">
            <div><span>Replay progress</span><strong>{replayStats.total}/{evaluationSummary.total || 300}</strong></div>
            <div><span>Correct</span><strong>{evaluationSummary.correct || 0}</strong></div>
            <div><span>Incorrect</span><strong>{evaluationSummary.incorrect || 0}</strong></div>
            <div><span>Sample accuracy</span><strong>{`${(toFiniteNumber(evaluationSummary.accuracy) * 100).toFixed(1)}%`}</strong></div>
          </div>

          <div className="evaluation-family-strip" aria-label="Rows per true family">
            {(modelInfo.classes || ['Benign', 'DDoS', 'DoS', 'MQTT', 'Recon', 'Spoofing']).map((family) => (
              <span key={family} style={{ '--family-color': FAMILY_COLORS[family] || FAMILY_COLORS.Unknown }}>
                <i />{family} <strong>{evaluationSummary.rows_per_family?.[family] || 0}</strong>
              </span>
            ))}
          </div>

          <div className="evaluation-controls">
            <div className="search-shell">
              <Search size={18} />
              <input
                value={evaluationQuery}
                onChange={(event) => setEvaluationQuery(event.target.value)}
                placeholder="Search sample, subclass, true or predicted family"
              />
            </div>
            <FilterSelect label="True family" value={evaluationFamily} onChange={setEvaluationFamily}>
              <option value="ALL">All six families</option>
              {(modelInfo.classes || []).map((family) => <option key={family} value={family}>{family}</option>)}
            </FilterSelect>
            <FilterSelect label="Result" value={evaluationResult} onChange={setEvaluationResult}>
              <option value="ALL">All predictions</option>
              <option value="CORRECT">Correct only</option>
              <option value="INCORRECT">Incorrect only</option>
            </FilterSelect>
          </div>

          {evaluationLoading ? (
            <div className="evaluation-state"><RefreshCw className="spin" size={22} />Loading 300 held-out samples…</div>
          ) : evaluationError ? (
            <div className="evaluation-state error"><AlertTriangle size={22} />{evaluationError}</div>
          ) : (
            <>
              <div className="evaluation-table-wrap">
                <table className="evaluation-table">
                  <thead>
                    <tr>
                      <th>Sample</th>
                      <th>True family</th>
                      <th>Prediction</th>
                      <th>Predicted-class confidence</th>
                      <th>Result</th>
                      <th>Official source row</th>
                      <th>Report</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleEvaluationSamples.map((sample) => (
                      <tr key={sample.log_id}>
                        <td><strong>{sample.log_id}</strong><small>{sample.attack_subclass}</small></td>
                        <td><span className="family-pill" style={{ '--family-color': FAMILY_COLORS[sample.true_family] || FAMILY_COLORS.Unknown }}>{sample.true_family}</span></td>
                        <td><span className="family-pill" style={{ '--family-color': FAMILY_COLORS[sample.traffic_class] || FAMILY_COLORS.Unknown }}>{sample.traffic_class}</span></td>
                        <td>{(toFiniteNumber(sample.model_probability) * 100).toFixed(1)}%</td>
                        <td>
                          <span className={`evaluation-result ${sample.prediction_correct ? 'correct' : 'incorrect'}`}>
                            {sample.prediction_correct ? <CheckCircle2 size={14} /> : <X size={14} />}
                            {sample.prediction_correct ? 'Correct' : 'Incorrect'}
                          </span>
                        </td>
                        <td><small>{sample.destination_target}<br />row {sample.source_row_number}</small></td>
                        <td>
                          <div className="evaluation-actions">
                            <button type="button" onClick={() => handlePreviewReport(sample)}><Eye size={15} />Preview</button>
                            <button type="button" onClick={() => handleInstallReport(sample)}><Download size={15} />PDF</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="evaluation-pagination">
                <span>
                  Showing {filteredEvaluationSamples.length ? (evaluationPage - 1) * EVALUATION_PAGE_SIZE + 1 : 0}–{Math.min(evaluationPage * EVALUATION_PAGE_SIZE, filteredEvaluationSamples.length)} of {filteredEvaluationSamples.length}
                </span>
                <div>
                  <button type="button" disabled={evaluationPage <= 1} onClick={() => setEvaluationPage((page) => page - 1)}>Previous</button>
                  <strong>Page {evaluationPage} / {evaluationPageCount}</strong>
                  <button type="button" disabled={evaluationPage >= evaluationPageCount} onClick={() => setEvaluationPage((page) => page + 1)}>Next</button>
                </div>
              </div>
              <p className="dataset-note evaluation-note">
                Each evaluation report includes the saved CatBoost prediction, model-derived risk, 12 features, and class probabilities. Opening a report queries official PCAP indicators through OTX/VirusTotal and exact deployed dependency versions through OSV/NVD. These contextual evidence planes are kept separate from the numeric TEST row.
              </p>
            </>
          )}
        </section>
        )}

        <section className="intelligence-surface surface" id="intelligence" aria-label="Live intelligence sources">
          <div className="section-heading intelligence-heading">
            <div>
              <p className="eyebrow">Live CTI enrichment</p>
              <h2>Four-source intelligence status</h2>
              <p className="section-description">Sources are queried on demand when an event contains a supported public indicator.</p>
            </div>
            <button
              className="soft-button"
              type="button"
              onClick={() => loadIntelligence(true)}
              disabled={intelligenceLoading}
            >
              <RefreshCw className={intelligenceLoading ? 'spin' : ''} size={16} />
              {intelligenceLoading ? 'Refreshing' : 'Scan dependencies'}
            </button>
          </div>

          <div className="source-grid">
            <SourceCard
              icon={Database}
              label="OSV"
              detail="Dependency matching"
              source={sourceStatus.osv}
            />
            <SourceCard
              icon={Globe2}
              label="NVD"
              detail="CVSS and KEV metadata"
              source={sourceStatus.nvd}
            />
            <SourceCard
              icon={Radio}
              label="AlienVault OTX"
              detail="Community IoC pulses"
              source={sourceStatus.otx}
            />
            <SourceCard
              icon={Fingerprint}
              label="VirusTotal"
              detail="Multi-engine reputation"
              source={sourceStatus.virustotal}
            />
          </div>

          <div className="posture-strip architecture-strip">
            <div>
              <span>Detection model</span>
              <strong>CatBoost multiclass</strong>
            </div>
            <div>
              <span>Input schema</span>
              <strong>{modelInfo.features?.length || 12} flow features</strong>
            </div>
            <div>
              <span>Attack classes</span>
              <strong>{modelInfo.classes?.length || 6} classes</strong>
            </div>
            <div>
              <span>CTI evidence</span>
              <strong>{databaseStatus.counts?.cti_lookup_results || 0} records</strong>
            </div>
            <div>
              <span>Alert queue</span>
              <strong>{databaseStatus.counts?.alerts || 0} alerts</strong>
            </div>
            <div>
              <span>Database</span>
              <strong>{databaseStatus.backend === 'postgresql' ? 'Supabase PostgreSQL' : databaseStatus.backend}</strong>
            </div>
          </div>
          <p className="posture-message">
            Optional dependency scan: {posture.state || 'pending'} · {posture.packages_scanned || 0} packages · {posture.vulnerability_count || 0} findings · max CVSS {Number(posture.max_cvss || 0).toFixed(1)}
          </p>
        </section>

        <section className="analytics-grid single-panel" aria-label="Live exploratory data analysis">
          {false && (
          <div className="surface dataset-eda">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Training dataset EDA</p>
                <h2>CICIoMT2024 class balance</h2>
                <p className="section-description">Actual family counts saved with the deployed model, before and after training-set balancing.</p>
              </div>
              <Database size={18} />
            </div>
            <div className="dataset-summary">
              <div><span>Original rows</span><strong>{sourceTrainingRows.toLocaleString()}</strong></div>
              <div><span>Balanced rows</span><strong>{balancedTrainingRows.toLocaleString()}</strong></div>
              <div><span>Families</span><strong>{balanceData.length || 6}</strong></div>
            </div>
            <div className="balance-legend" aria-label="Class balance legend">
              <span><i className="original" />Original</span>
              <span><i className="balanced" />Balanced training</span>
            </div>
            <div className="balance-chart">
              {balanceData.map((item) => (
                <div className="balance-row" key={item.family}>
                  <strong>{item.family}</strong>
                  <div className="balance-bars">
                    <span className="original" style={{ width: `${(item.source_rows / maxBalanceRows) * 100}%` }}>
                      <em>{Number(item.source_rows).toLocaleString()}</em>
                    </span>
                    <span className="balanced" style={{ width: `${(item.balanced_rows / maxBalanceRows) * 100}%` }}>
                      <em>{Number(item.balanced_rows).toLocaleString()}</em>
                    </span>
                  </div>
                </div>
              ))}
            </div>
            <p className="dataset-note">Balancing applies only to the training split. The official test split remains untouched for evaluation.</p>
          </div>
          )}

          <div className="surface">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Live EDA</p>
                <h2>Live prediction distribution</h2>
                <p className="section-description">Running distribution for the evaluation replay plus persisted investigations currently visible in the dashboard.</p>
              </div>
              <AlertTriangle size={18} />
            </div>
            <div className="dataset-summary live-replay-summary" aria-label="Live replay EDA summary">
              <div><span>Streamed</span><strong>{replayStats.total}/{evaluationSummary.total || 300}</strong></div>
              <div><span>Correct so far</span><strong>{replayStats.correct}</strong></div>
              <div><span>Running accuracy</span><strong>{replayStats.total ? `${(replayStats.accuracy * 100).toFixed(1)}%` : 'Waiting'}</strong></div>
            </div>
            <div className="pie-layout">
              <ResponsiveContainer width="52%" height={220}>
                <PieChart>
                  <Pie data={familyData} dataKey="value" nameKey="name" innerRadius={56} outerRadius={88} paddingAngle={3}>
                    {familyData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="tlp-legend">
                {familyData.map((entry) => (
                  <div key={entry.name}>
                    <span style={{ backgroundColor: entry.color }} />
                    <strong>{entry.name}</strong>
                    <em>{entry.value}</em>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {false && (
        <section className="category-grid" aria-label="Telemetry categories">
          {categoryData.map((item) => {
            const CategoryIcon = item.icon;
            return (
              <div className="category-tile" key={item.key}>
                <span style={{ color: item.color }}>
                  <CategoryIcon size={20} />
                </span>
                <div>
                  <strong>{item.label}</strong>
                  <p>{item.count} events</p>
                </div>
              </div>
            );
          })}
        </section>
        )}

        <section className="surface traffic-surface" id="traffic">
          <div className="section-heading traffic-heading">
            <div>
              <p className="eyebrow">Live stream</p>
              <h2>Traffic events and incident reports</h2>
            </div>
            <span>{filteredLogs.length} visible</span>
          </div>

          <div className="filter-panel" aria-label="Traffic filters">
            <div className="search-shell">
              <Search size={18} />
              <input
                value={filters.query}
                onChange={(event) => updateFilter('query', event.target.value)}
                placeholder="Search log, IP, category, or department"
              />
            </div>

            <FilterSelect label="Category" value={filters.category} onChange={(value) => updateFilter('category', value)}>
              <option value="ALL">All categories</option>
              {Object.entries(CATEGORY_META).map(([key, meta]) => (
                <option key={key} value={key}>
                  {meta.label}
                </option>
              ))}
            </FilterSelect>

            <FilterSelect label="TLP" value={filters.tlp} onChange={(value) => updateFilter('tlp', value)}>
              <option value="ALL">All TLP</option>
              {Object.keys(TLP_META).map((key) => (
                <option key={key} value={key}>
                  {key}
                </option>
              ))}
            </FilterSelect>

            <label className="date-filter">
              <Calendar size={16} />
              <input type="date" value={filters.date} onChange={(event) => updateFilter('date', event.target.value)} />
            </label>

            <label className="date-filter compact">
              <Clock3 size={16} />
              <input type="time" value={filters.timeFrom} onChange={(event) => updateFilter('timeFrom', event.target.value)} />
            </label>

            <label className="date-filter compact">
              <Clock3 size={16} />
              <input type="time" value={filters.timeTo} onChange={(event) => updateFilter('timeTo', event.target.value)} />
            </label>

            {hasActiveFilters && (
              <button className="soft-button" type="button" onClick={resetFilters}>
                <X size={16} />
                Reset
              </button>
            )}
          </div>

          <div className="log-list" id="reports">
            {filteredLogs.length === 0 ? (
              <div className="empty-state">
                <RefreshCw size={28} />
                <strong>No events match the current filters.</strong>
                <p>Live telemetry will appear here as soon as the backend stream is available.</p>
              </div>
            ) : (
              filteredLogs.map((log) => (
                <LogRow
                  key={`${log.log_id}-${log.timestamp}-${log.destination_target}`}
                  log={log}
                  onPreview={handlePreviewReport}
                  onInstall={handleInstallReport}
                />
              ))
            )}
          </div>
        </section>
      </main>

      {selectedReportLog && (
        <ReportModal
          log={selectedReportLog}
          reportRef={reportRef}
          onClose={() => setSelectedReportLog(null)}
          onInstall={() => handleInstallReport(selectedReportLog)}
          onRefreshLive={() => refreshLiveEvidence(selectedReportLog, true)}
          liveEvidenceLoading={liveEvidenceLoading}
          liveEvidenceMessage={liveEvidenceMessage}
        />
      )}
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, accent, helper }) {
  return (
    <div className="metric-card" style={{ '--accent': accent }}>
      <span className="metric-icon">
        <Icon size={19} />
      </span>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <small>{helper}</small>
      </div>
    </div>
  );
}

function ValidationMetric({ label, value }) {
  const normalized = Number(value);
  return (
    <div className="validation-metric">
      <span>{label}</span>
      <strong>{Number.isFinite(normalized) ? `${(normalized * 100).toFixed(1)}%` : 'Loading'}</strong>
    </div>
  );
}

function SourceCard({ icon: Icon, label, detail, source }) {
  const status = source?.status || 'pending';
  const statusLabel = {
    live: 'Live · query successful',
    ready: 'Live API ready',
    needs_key: 'API key needed',
    error: 'Unavailable',
    pending: 'Checking',
  }[status] || status;

  return (
    <article className={`source-card ${status}`}>
      <span className="source-icon">
        <Icon size={19} />
      </span>
      <div>
        <strong>{label}</strong>
        <p>{detail}</p>
      </div>
      <span className="source-state">{statusLabel}</span>
    </article>
  );
}

function FilterSelect({ label, value, onChange, children }) {
  return (
    <label className="select-filter">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {children}
      </select>
      <ChevronDown size={16} />
    </label>
  );
}

function LogRow({ log, onPreview, onInstall }) {
  const tlpMeta = TLP_META[log.tlp] || TLP_META['TLP:CLEAR'];
  const severityMeta = SEVERITY_META[log.severity] || SEVERITY_META.low;
  const categoryMeta = CATEGORY_META[log.category] || { label: log.category, icon: Activity, color: '#92a4b7' };
  const CategoryIcon = categoryMeta.icon;
  const isThreat = log.evaluation_mode ? log.traffic_class !== 'Benign' : log.is_threat === 1;
  const statusLabel = getLogThreatStatus(log);

  return (
    <article className={`log-row severity-${severityMeta.tone}`}>
      <div className="log-main">
        <div className="log-title">
          <span className="category-chip" style={{ '--chip': categoryMeta.color }}>
            <CategoryIcon size={14} />
            {categoryMeta.label}
          </span>
          <strong>{log.log_id}</strong>
          <span className={`severity-chip ${severityMeta.tone}`}>
            {log.evaluation_mode ? getModelScoreLabel(log) : severityMeta.label}
          </span>
          <span className={`tlp-chip ${tlpMeta.tone}`}>{log.tlp}</span>
        </div>
        <p>
          <span>{log.source_ip}</span>
          <em>to</em>
          <span>{log.destination_target}</span>
        </p>
        <div className="log-meta">
          <span>{log.department}</span>
          <span>{log.data_mb} KB</span>
          <span>
            {Math.round(log.attack_probability * 100)}% non-Benign probability ·{' '}
            {log.evaluation_mode ? getModelScoreLabel(log) : `${log.severity} severity`}
          </span>
          <span>{log.date} {log.timestamp}</span>
          <span>Intel: {log.intel_verdict}</span>
        </div>
      </div>
      <div className="log-actions">
        <span className={isThreat ? 'status-tag threat' : 'status-tag safe'}>
          {isThreat ? <ShieldAlert size={14} /> : <CheckCircle2 size={14} />}
          {statusLabel}
        </span>
        <button type="button" onClick={() => onPreview(log)}>
          <Eye size={15} />
          Preview
        </button>
        <button type="button" className="install-report-button" onClick={() => onInstall(log)}>
          <FileText size={15} />
          Download PDF
        </button>
      </div>
    </article>
  );
}

function ReportModal({
  log,
  reportRef,
  onClose,
  onInstall,
  onRefreshLive,
  liveEvidenceLoading,
  liveEvidenceMessage,
}) {
  return (
    <div className="report-modal-backdrop" role="presentation">
      <section className="report-modal" role="dialog" aria-modal="true" aria-labelledby="report-title">
        <div className="report-modal-toolbar">
          <div>
            <p className="eyebrow">Report preview</p>
            <h2 id="report-title">{log.log_id}</h2>
          </div>
          <div className="report-toolbar-actions">
            {(log.evaluation_mode || Boolean(log.live_evidence_endpoint)) && (
              <button type="button" onClick={onRefreshLive} disabled={liveEvidenceLoading}>
                <RefreshCw className={liveEvidenceLoading ? 'spin' : ''} size={16} />
                {liveEvidenceLoading
                  ? 'Connecting...'
                  : log.evaluation_mode
                    ? 'Run live API lookup'
                    : 'Refresh all APIs live'}
              </button>
            )}
            <button type="button" onClick={onInstall}>
              <Download size={16} />
              Download PDF
            </button>
            <button type="button" className="report-close-button" onClick={onClose} aria-label="Close report preview">
              <X size={18} />
            </button>
          </div>
        </div>

        {(log.evaluation_mode || Boolean(log.live_evidence_endpoint)) && (
          <p className={`report-live-status ${log.evidence_mode !== 'not_applicable' ? 'is-live' : ''}`}>
            {liveEvidenceMessage}
          </p>
        )}

        <ReportDocument log={log} reportRef={reportRef} />
      </section>
    </div>
  );
}

function ProviderResult({ provider }) {
  const observations = (Array.isArray(provider.observations) ? provider.observations : [])
    .filter((observation) => observation?.indicator && observation?.metrics);
  if (!observations.length) {
    return <p className="provider-fallback">{provider.result}</p>;
  }

  return (
    <div className="provider-observation-list">
      {observations.map((observation, index) => {
        const view = providerObservationView(provider.provider_id, observation);
        return (
          <article className="provider-observation" key={`${observation.indicator}-${index}`}>
            <div className="provider-observation-head">
              <strong>{observation.indicator}</strong>
              <span className={`verdict-pill ${view.verdict.tone}`}>{view.verdict.label}</span>
            </div>
            <p>{view.summary}</p>
            <div className="provider-facts">
              {view.facts.map(([label, value]) => (
                <span key={label}><b>{label}</b>{String(value)}</span>
              ))}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function ReportDocument({ log, reportRef }) {
  const tlpMeta = TLP_META[log.tlp] || TLP_META['TLP:CLEAR'];
  const severityMeta = SEVERITY_META[log.severity] || SEVERITY_META.low;
  const recommendations = getReportRecommendations(log);
  const providers = getProviderRows(log);
  const reasons = Array.isArray(log.risk_reasons) ? log.risk_reasons : [];
  const features = Object.entries(log.features || {});
  const probabilities = Object.entries(log.class_probabilities || {});

  return (
    <article className="report-document" ref={reportRef}>
      <header className="report-header">
        <div>
          <p>Healthcare CTI SOC</p>
          <h1>{log.evaluation_mode ? 'Model Evaluation Report' : 'Security Analysis Report'}</h1>
          <span>
            {log.evaluation_mode
              ? 'Report type: held-out model evaluation. This is not a live incident verdict. Ground truth is available, and contextual CTI is not attributed to the numeric TEST row.'
              : 'Report type: live incident investigation. The model result is fused with evidence returned for indicators actually present in this event.'}
          </span>
        </div>
        <div className="report-header-badges">
          <strong style={{ backgroundColor: severityMeta.color }}>
            {log.evaluation_mode ? getModelScoreLabel(log) : severityMeta.label}
          </strong>
          <strong style={{ backgroundColor: tlpMeta.color }}>{log.sharing_classification || log.tlp}</strong>
        </div>
      </header>

      <section className="report-summary-grid" aria-label="Report summary">
        {getReportSummary(log).map(([label, value]) => (
          <div key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </section>

      {features.length > 0 && (
        <section className="report-section report-model-grid">
          <div>
            <h2>12 Model Features</h2>
            <div className="report-table-wrap">
              <table><tbody>
                {features.map(([feature, value]) => (
                  <tr key={feature}><th>{feature}</th><td>{String(value)}</td></tr>
                ))}
              </tbody></table>
            </div>
          </div>
          <div>
            <h2>Class Probabilities</h2>
            <div className="report-table-wrap">
              <table><tbody>
                {probabilities.map(([family, value]) => (
                  <tr key={family}><th>{family}</th><td>{(toFiniteNumber(value) * 100).toFixed(2)}%</td></tr>
                ))}
              </tbody></table>
            </div>
          </div>
        </section>
      )}

      <section className="report-section">
        <h2>Full Log Details</h2>
        <div className="report-table-wrap">
          <table>
            <tbody>
              {getReportRows(log).map(([label, value]) => (
                <tr key={label}>
                  <th>{label}</th>
                  <td>{typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value ?? '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="report-section">
        <h2>{getEvidenceHeading(log)}</h2>
        <p className="report-method-note">
          {getEvidenceMethodNote(log)}
        </p>
        <div className="report-table-wrap">
          <table className="report-provider-table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Provider status</th>
                <th>Evidence result</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((provider) => (
                <tr key={provider.provider_id}>
                  <td><strong>{provider.provider}</strong></td>
                  <td>{providerStatusLabel(provider)}</td>
                  <td><ProviderResult provider={provider} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {reasons.length > 0 && (
        <section className="report-section">
          <h2>Decision Reasons</h2>
          <ul>
            {reasons.map((reason) => <li key={reason}>{reason}</li>)}
          </ul>
        </section>
      )}

      <section className="report-section">
        <h2>Evidence-Linked Recommended Actions</h2>
        <p className="report-method-note">
          {log.recommendation_method || 'Recommendations are local policy guidance; verify before operational action.'}
        </p>
        <ul className="report-recommendations">
          {recommendations.map((item) => (
            <li key={`${item.priority}-${item.action}`}>
              <strong>[{item.priority}] {item.action}</strong>
              <span><b>Problem addressed:</b> {item.problem}</span>
              <span><b>Evidence:</b> {item.evidence}</span>
              <span><b>Sources:</b> {item.evidenceSources.join(', ') || 'Local policy'}</span>
            </li>
          ))}
        </ul>
      </section>
    </article>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) {
    return null;
  }

  return (
    <div className="chart-tooltip">
      {label && <strong>{label}</strong>}
      {payload.map((item) => (
        <span key={item.dataKey || item.name}>
          {item.name}: {item.value}
        </span>
      ))}
    </div>
  );
}
