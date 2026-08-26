import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bell,
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
const LOG_STORAGE_KEY = 'healthcare_soc_logs_v8';
const MAX_LOGS = 120;
const EVALUATION_PAGE_SIZE = 25;
const PROVIDER_ORDER = ['otx', 'virustotal', 'osv', 'nvd'];
const PROVIDER_NAMES = {
  otx: 'AlienVault OTX',
  virustotal: 'VirusTotal',
  osv: 'OSV',
  nvd: 'NIST NVD',
};
const DEDICATED_REPORT_FIELDS = new Set([
  'indicator_evidence',
  'provider_evidence',
  'recommended_actions',
  'recommendation_method',
  'risk_reasons',
  'vulnerability_posture',
  'features',
  'class_probabilities',
  'model_details',
]);

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

const normalizeLog = (log) => ({
  ...log,
  log_id: String(log.log_id || `LOG-${Date.now()}`),
  category: 'IoMT network flows',
  department: String(log.department || 'General'),
  destination_target: String(log.destination_target || '0.0.0.0'),
  source_ip: String(log.source_ip || '0.0.0.0'),
  data_mb: toFiniteNumber(log.data_mb),
  is_threat: toFiniteNumber(log.is_threat),
  is_in_otx: Boolean(log.is_in_otx),
  risk_level: String(log.risk_level || 'low'),
  risk_probability: toFiniteNumber(log.risk_probability),
  model_probability: toFiniteNumber(log.model_probability),
  intel_verdict: String(log.intel_verdict || 'unknown'),
  tlp: String(log.tlp || 'TLP:CLEAR'),
  timestamp: String(log.timestamp || new Date().toLocaleTimeString('en-GB')),
  date: String(log.date || new Date().toISOString().slice(0, 10)),
});

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
  key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace(/\bIp\b/g, 'IP')
    .replace(/\bOtx\b/g, 'OTX')
    .replace(/\bTlp\b/g, 'TLP');

const getLogThreatStatus = (log) => (log.is_threat === 1 || log.tlp === 'TLP:RED' || log.is_in_otx ? 'Threat' : 'Safe');

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
  if (provider.status === 'available') return 'Queried — available';
  if (provider.status === 'not_applicable') return 'Not applicable';
  if (provider.status === 'not_configured') return 'Applicable — not configured';
  if (provider.status === 'not_queried') return 'Applicable — not queried';
  if (provider.status === 'unavailable') return 'Queried — unavailable';
  return 'Not recorded';
};

const getReportRows = (log) => {
  const preferredOrder = [
    'log_id',
    'date',
    'timestamp',
    'category',
    'traffic_class',
    'department',
    'source_ip',
    'destination_target',
    'data_mb',
    'data_unit',
    'is_threat',
    'is_in_otx',
    'risk_level',
    'risk_probability',
    'model_probability',
    'intel_verdict',
    'tlp',
  ];
  const seen = new Set();
  const rows = [];

  preferredOrder.forEach((key) => {
    if (Object.prototype.hasOwnProperty.call(log, key)) {
      seen.add(key);
      rows.push([formatReportLabel(key), log[key]]);
    }
  });

  Object.entries(log).forEach(([key, value]) => {
    if (!seen.has(key) && !DEDICATED_REPORT_FIELDS.has(key) && (value === null || typeof value !== 'object')) {
      rows.push([formatReportLabel(key), value]);
    }
  });

  return rows;
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
  if (log.tlp === 'TLP:RED' || log.is_in_otx) {
    fallback = [
      'Escalate to the incident response owner immediately.',
      'Validate source and destination assets before allowing continued communication.',
      'Preserve related telemetry and attach this report to the incident record.',
    ];
  } else if (log.tlp === 'TLP:AMBER' || log.is_threat === 1) {
    fallback = [
      'Review the event with the responsible department.',
      'Correlate with endpoint and firewall telemetry for the same time window.',
      'Keep sharing limited to the response team until the event is confirmed.',
    ];
  } else if (log.tlp === 'TLP:GREEN') {
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
  const status = getLogThreatStatus(log);
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
        <td>${escapeHtml(provider.result)}</td>
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
  const posture = log.vulnerability_posture || {};
  const postureSummary = `State ${posture.state || 'not recorded'}; ${toFiniteNumber(posture.packages_scanned)} packages scanned; ${toFiniteNumber(posture.vulnerability_count)} vulnerabilities; maximum CVSS ${toFiniteNumber(posture.max_cvss).toFixed(1)}.`;
  const featureRows = Object.entries(log.features || {})
    .map(([feature, value]) => `<tr><th>${escapeHtml(feature)}</th><td>${escapeHtml(value)}</td></tr>`)
    .join('');
  const probabilityRows = Object.entries(log.class_probabilities || {})
    .map(([family, value]) => `<tr><th>${escapeHtml(family)}</th><td>${escapeHtml(`${(toFiniteNumber(value) * 100).toFixed(2)}%`)}</td></tr>`)
    .join('');
  const reportTitle = log.evaluation_mode ? 'Official TEST Evaluation Report' : 'Incident Report';
  const reportDescription = log.evaluation_mode
    ? 'Generated from a held-out CICIoMT2024 Official TEST row; this record was never used for training or balancing.'
    : 'Generated from an analyzed IoMT network-flow event and its CTI evidence.';

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Incident Report - ${escapeHtml(log.log_id)}</title>
    <style>
      body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; color: #16222c; background: #f4f7fa; }
      main { max-width: 920px; margin: 24px auto; padding: 34px; background: #fff; border: 1px solid #d8e1e8; }
      header { display: flex; justify-content: space-between; gap: 24px; border-bottom: 3px solid #167f92; padding-bottom: 18px; }
      h1, h2 { margin: 0; }
      h1 { font-size: 25px; }
      h2 { margin-top: 26px; font-size: 18px; }
      p { margin: 8px 0 0; color: #637485; }
      .badge { align-self: flex-start; border-radius: 6px; padding: 8px 12px; color: #fff; background: ${tlpMeta.color}; font-weight: 800; }
      .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 22px; }
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
        <span class="badge">${escapeHtml(log.tlp)}</span>
      </header>
      <section class="summary" aria-label="Report summary">
        <div><span>Status</span><strong>${escapeHtml(status)}</strong></div>
        <div><span>Category</span><strong>${escapeHtml(log.category)}</strong></div>
        <div><span>Observed Time</span><strong>${escapeHtml(`${log.date} ${log.timestamp}`)}</strong></div>
      </section>
      <h2>Log Details</h2>
      <table><tbody>${rows}</tbody></table>
      ${featureRows ? `<h2>12 Model Features</h2><table><tbody>${featureRows}</tbody></table>` : ''}
      ${probabilityRows ? `<h2>Class Probabilities</h2><table><tbody>${probabilityRows}</tbody></table>` : ''}
      <h2>Four-Database Evidence</h2>
      <table class="provider-table">
        <thead><tr><th>Provider</th><th>Query status</th><th>API result for this log</th></tr></thead>
        <tbody>${providerRows}</tbody>
      </table>
      <p><b>OSV/NVD dependency posture:</b> ${escapeHtml(postureSummary)}</p>
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
  const [logs, setLogs] = useState(loadSavedLogs);
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [lastSeen, setLastSeen] = useState(null);
  const [selectedReportLog, setSelectedReportLog] = useState(null);
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
        setLogs((current) => {
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
      const [statusResponse, postureResponse, alertsResponse, databaseResponse, investigationsResponse, modelResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/api/intelligence/status`),
        fetch(`${API_BASE_URL}/api/vulnerabilities/posture`),
        fetch(`${API_BASE_URL}/api/alerts?limit=4`),
        fetch(`${API_BASE_URL}/api/database/status`),
        fetch(`${API_BASE_URL}/api/investigations?limit=${MAX_LOGS}`),
        fetch(`${API_BASE_URL}/api/model`),
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
        setLogs(persistedLogs);
        localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(persistedLogs));
      }
      if (modelResponse.ok) {
        setModelInfo(await modelResponse.json());
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
        const isThreat = log.is_threat === 1 || log.tlp === 'TLP:RED' || log.is_in_otx;
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
  const featureImportance = (modelInfo.feature_importance || []).slice(0, 8);
  const maxFeatureImportance = featureImportance[0]?.importance || 1;
  const balanceData = modelInfo.training_dataset?.balance_audit || [];
  const maxBalanceRows = Math.max(
    1,
    ...balanceData.flatMap((item) => [Number(item.source_rows) || 0, Number(item.balanced_rows) || 0]),
  );
  const sourceTrainingRows = balanceData.reduce((total, item) => total + (Number(item.source_rows) || 0), 0);
  const balancedTrainingRows = balanceData.reduce((total, item) => total + (Number(item.balanced_rows) || 0), 0);

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
    setLogs([]);
  };

  const resetFilters = () => {
    setFilters(DEFAULT_FILTERS);
  };

  const handlePreviewReport = (log) => {
    setSelectedReportLog(log);
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
      setLogs((current) => {
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
          <a href="#test-replay">
            <CheckCircle2 size={18} />
            TEST Replay
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
              <div><strong>TLP handling</strong><span>Automated traffic handling labels</span></div>
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
              {integrationLoading ? 'Analyzing...' : 'Run end-to-end test'}
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
            <h2>{stats.threats} of {stats.total} stored investigations are currently classified as threats.</h2>
            <p>
              Stage 1 uses the trained CatBoost IDS to classify network-flow behavior. Stage 2 queries OSV,
              NVD, AlienVault OTX, and VirusTotal for independent evidence before producing risk and response actions.
            </p>
          </div>
          <div className="risk-meter" style={{ '--risk': stats.riskScore }} aria-label={`Risk score ${stats.riskScore} percent`}>
            <span>{stats.riskScore}</span>
            <small>% threat ratio</small>
          </div>
        </section>

        <section className="metric-grid" aria-label="Security metrics">
          <MetricCard icon={ShieldAlert} label="Threat Predictions" value={stats.threats} accent="#e85d75" helper={`${databaseStatus.counts?.cti_lookup_results || 0} CTI evidence records`} />
          <MetricCard icon={ShieldCheck} label="Benign / Safe" value={stats.safe} accent="#3ab795" helper="No alert in stored window" />
          <MetricCard icon={Bell} label="Detected Families" value={Object.keys(stats.families).length} accent="#61b4d8" helper={`${modelInfo.classes?.length || 6} trained classes`} />
          <MetricCard icon={Database} label="Stored Investigations" value={databaseStatus.counts?.hospital_events || stats.total} accent="#d7b46a" helper="Supabase PostgreSQL" />
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
                  Kaggle replay: <strong>{Number(modelInfo.evaluation?.website_replay_rows || 300)}</strong> unique rows at <strong>{(toFiniteNumber(modelInfo.evaluation?.website_replay_accuracy || (284 / 300)) * 100).toFixed(1)}%</strong> sample accuracy with saved OTX, VirusTotal, OSV, and NVD evidence.
                </span>
              </div>
              <div className="pipeline-explainer">
                <div><span>1</span><strong>Detect</strong><p>CatBoost classifies 12 numeric flow features.</p></div>
                <div><span>2</span><strong>Enrich</strong><p>Four CTI APIs check relevant IoCs, CVEs, and packages.</p></div>
                <div><span>3</span><strong>Respond</strong><p>Risk fusion creates an alert and recommended actions.</p></div>
              </div>
            </div>
            <div className="feature-panel">
              <div className="panel-heading"><strong>Top feature importance</strong><span>Model explainability</span></div>
              {featureImportance.map((item) => (
                <div className="feature-row" key={item.feature}>
                  <div><span>{item.feature}</span><em>{Number(item.importance).toFixed(1)}%</em></div>
                  <i style={{ width: `${Math.max(4, (item.importance / maxFeatureImportance) * 100)}%` }} />
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="evaluation-replay surface" id="test-replay" aria-label="CICIoMT2024 Official TEST replay">
          <div className="section-heading evaluation-heading">
            <div>
              <p className="eyebrow">Held-out model evaluation</p>
              <h2>300-sample Official TEST replay</h2>
              <p className="section-description">
                Fifty unique rows from each of the six CICIoMT2024 families, sampled without replacement.
                These rows are used only for prediction and reporting—never for training, balancing, or tuning.
              </p>
            </div>
            <span className="model-badge">Official TEST · 50 × 6 families</span>
          </div>

          <div className="evaluation-summary" aria-label="Replay summary">
            <div><span>Samples</span><strong>{evaluationSummary.total || 300}</strong></div>
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
                      <th>Confidence</th>
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
                OTX, VirusTotal, OSV, and NVD are shown in every report. They are marked “Not applicable” for these rows because the official flow CSV contains numeric traffic features—not a public IoC, CVE, or package identifier.
              </p>
            </>
          )}
        </section>

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
          <div className="analyst-queue" aria-label="Persisted analyst alert queue">
            <div className="analyst-queue-heading">
              <div>
                <p className="eyebrow">Audit trail</p>
                <h3>Persisted analyst queue</h3>
              </div>
              <span>{analystAlerts.length} latest</span>
            </div>
            {analystAlerts.length ? (
              <div className="analyst-alert-list">
                {analystAlerts.map((alert) => (
                  <article key={alert.id} className={`analyst-alert ${alert.severity}`}>
                    <div>
                      <strong>{alert.title}</strong>
                      <p>{alert.event_id || 'Static assessment'} · {alert.classification.replace(/_/g, ' ')}</p>
                    </div>
                    <span>{Math.round(alert.final_score * 100)}% · {alert.status}</span>
                  </article>
                ))}
              </div>
            ) : (
              <p className="analyst-empty">No persisted alerts meet the review threshold yet.</p>
            )}
          </div>
          <p className="posture-message">
            Optional dependency scan: {posture.state || 'pending'} · {posture.packages_scanned || 0} packages · {posture.vulnerability_count || 0} findings · max CVSS {Number(posture.max_cvss || 0).toFixed(1)}
          </p>
        </section>

        <section className="analytics-grid" aria-label="Training and live exploratory data analysis">
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

          <div className="surface">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Live EDA</p>
                <h2>Live prediction distribution</h2>
                <p className="section-description">Attack families predicted from investigations currently stored in Supabase.</p>
              </div>
              <AlertTriangle size={18} />
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
  const categoryMeta = CATEGORY_META[log.category] || { label: log.category, icon: Activity, color: '#92a4b7' };
  const CategoryIcon = categoryMeta.icon;
  const isThreat = log.is_threat === 1 || log.tlp === 'TLP:RED' || log.is_in_otx;

  return (
    <article className={`log-row ${tlpMeta.tone}`}>
      <div className="log-main">
        <div className="log-title">
          <span className="category-chip" style={{ '--chip': categoryMeta.color }}>
            <CategoryIcon size={14} />
            {categoryMeta.label}
          </span>
          <strong>{log.log_id}</strong>
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
          <span>{Math.round(log.risk_probability * 100)}% {log.risk_level} risk</span>
          <span>{log.date} {log.timestamp}</span>
          <span>Intel: {log.intel_verdict}</span>
        </div>
      </div>
      <div className="log-actions">
        <span className={isThreat ? 'status-tag threat' : 'status-tag safe'}>
          {isThreat ? <ShieldAlert size={14} /> : <CheckCircle2 size={14} />}
          {isThreat ? 'Threat' : 'Safe'}
        </span>
        <button type="button" onClick={() => onPreview(log)}>
          <Eye size={15} />
          Preview
        </button>
        <button type="button" className="install-report-button" onClick={() => onInstall(log)}>
          <FileText size={15} />
          Install
        </button>
      </div>
    </article>
  );
}

function ReportModal({ log, reportRef, onClose, onInstall }) {
  return (
    <div className="report-modal-backdrop" role="presentation">
      <section className="report-modal" role="dialog" aria-modal="true" aria-labelledby="report-title">
        <div className="report-modal-toolbar">
          <div>
            <p className="eyebrow">Report preview</p>
            <h2 id="report-title">{log.log_id}</h2>
          </div>
          <div className="report-toolbar-actions">
            <button type="button" onClick={onInstall}>
              <Download size={16} />
              Install Report
            </button>
            <button type="button" className="report-close-button" onClick={onClose} aria-label="Close report preview">
              <X size={18} />
            </button>
          </div>
        </div>

        <ReportDocument log={log} reportRef={reportRef} />
      </section>
    </div>
  );
}

function ReportDocument({ log, reportRef }) {
  const tlpMeta = TLP_META[log.tlp] || TLP_META['TLP:CLEAR'];
  const status = getLogThreatStatus(log);
  const recommendations = getReportRecommendations(log);
  const providers = getProviderRows(log);
  const reasons = Array.isArray(log.risk_reasons) ? log.risk_reasons : [];
  const posture = log.vulnerability_posture || {};
  const features = Object.entries(log.features || {});
  const probabilities = Object.entries(log.class_probabilities || {});

  return (
    <article className="report-document" ref={reportRef}>
      <header className="report-header">
        <div>
          <p>Healthcare CTI SOC</p>
          <h1>{log.evaluation_mode ? 'Official TEST Evaluation Report' : 'Incident Report'}</h1>
          <span>
            {log.evaluation_mode
              ? 'Generated from a held-out CICIoMT2024 Official TEST row that was never used for training or balancing.'
              : 'Generated from an analyzed IoMT network-flow event and its CTI evidence.'}
          </span>
        </div>
        <strong style={{ backgroundColor: tlpMeta.color }}>{log.tlp}</strong>
      </header>

      <section className="report-summary-grid" aria-label="Report summary">
        <div>
          <span>Status</span>
          <strong>{status}</strong>
        </div>
        <div>
          <span>Category</span>
          <strong>{log.category}</strong>
        </div>
        <div>
          <span>Observed Time</span>
          <strong>{log.date} {log.timestamp}</strong>
        </div>
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
        <h2>Four-Database Evidence</h2>
        <div className="report-table-wrap">
          <table className="report-provider-table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Query status</th>
                <th>API result for this log</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((provider) => (
                <tr key={provider.provider_id}>
                  <td><strong>{provider.provider}</strong></td>
                  <td>{providerStatusLabel(provider)}</td>
                  <td>{provider.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="report-posture-note">
          <strong>OSV/NVD dependency posture:</strong>{' '}
          State {posture.state || 'not recorded'}; {toFiniteNumber(posture.packages_scanned)} packages scanned;{' '}
          {toFiniteNumber(posture.vulnerability_count)} vulnerabilities; maximum CVSS{' '}
          {toFiniteNumber(posture.max_cvss).toFixed(1)}.
        </p>
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
