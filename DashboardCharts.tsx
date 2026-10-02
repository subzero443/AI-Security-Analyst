import { ArrowUpRight } from 'lucide-react'
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
type HeaderCoverage = { label: string; percent: number; observedOn: number; responseCount: number }

const severityColors = ['#fb5b5b', '#ff8a52', '#f3bd4f', '#70c99c']
const severityNames: Severity[] = ['Critical', 'High', 'Medium', 'Low']

export default function DashboardCharts({
  headerCoverage,
  responseCount,
  severityCounts,
  isLive,
  isDemo,
  onViewFindings,
}: {
  headerCoverage: HeaderCoverage[]
  responseCount: number
  severityCounts: Record<Severity, number>
  isLive: boolean
  isDemo: boolean
  onViewFindings: () => void
}) {
  const severityData = severityNames.map((name) => ({ name, value: severityCounts[name] }))
  const totalFindings = severityData.reduce((total, item) => total + item.value, 0)

  return (
    <section className="analysis-grid">
    <article className="panel risk-panel">
          <div className="panel-heading"><div><div className="panel-kicker">{isDemo ? 'DEMO RESPONSE HEADERS' : 'OBSERVED RESPONSE HEADERS'}</div><h2>Security header coverage</h2></div><span className={isDemo ? 'demo-tag' : 'chart-source'}>{isDemo ? 'DEMO ONLY' : `${responseCount} responses`}</span></div>
          <div className="chart-summary"><span className="chart-score">{isLive || isDemo ? `${headerCoverage.filter((item) => item.observedOn > 0).length}/${headerCoverage.length}` : '—'}</span><span className="chart-score-label">header types observed</span><span className="chart-note">{isLive || isDemo ? `across ${responseCount} endpoints` : 'Run a scan to collect evidence'}</span></div>
          <div className="risk-chart">{(isLive || isDemo) && responseCount > 0 ? <ResponsiveContainer width="100%" height="100%"><BarChart data={headerCoverage} layout="vertical" margin={{ top: 2, right: 18, left: 0, bottom: 2 }}><XAxis type="number" domain={[0, 100]} tickFormatter={(value: number) => `${value}%`} axisLine={false} tickLine={false} tick={{ fill: '#78848d', fontSize: 9 }} /><YAxis type="category" dataKey="label" width={125} axisLine={false} tickLine={false} tick={{ fill: '#a0acb1', fontSize: 9 }} /><Tooltip formatter={(value) => [`${value}%`, 'Responses']} contentStyle={{ background: '#161d23', border: '1px solid #303a42', borderRadius: 7, color: '#e7ecef', fontSize: 11 }} labelStyle={{ color: '#9aa7ae' }} /><Bar dataKey="percent" radius={[0, 3, 3, 0]} barSize={9}>{headerCoverage.map((item) => <Cell key={item.label} fill={item.percent === 100 ? '#79d894' : item.percent > 0 ? '#f3bd4f' : '#fb7770'} />)}</Bar></BarChart></ResponsiveContainer> : <div className="risk-empty">{isLive ? 'No successful HTTP responses to chart.' : 'Header coverage appears after your first scan.'}</div>}</div>
        <div className="chart-legend"><span><i className="legend-dot legend-green" /> Present on all checked responses</span><span className="chart-source">Partial or missing shown in amber/red</span></div>
      </article>
      <article className="panel breakdown-panel">
        <div className="panel-heading"><div><div className="panel-kicker">FINDINGS BY SEVERITY</div><h2>Risk breakdown</h2></div><button className="icon-button panel-more" title="View all findings" aria-label="View all findings" onClick={onViewFindings}><ArrowUpRight size={16} /></button></div>
        <div className="breakdown-body"><div className="donut-wrap"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius="68%" outerRadius="91%" paddingAngle={5} stroke="none">{severityColors.map((color) => <Cell key={color} fill={color} />)}</Pie><Tooltip contentStyle={{ background: '#161d23', border: '1px solid #303a42', borderRadius: 7, color: '#e7ecef', fontSize: 12 }} /></PieChart></ResponsiveContainer><div className="donut-center"><strong>{String(totalFindings).padStart(2, '0')}</strong><small>total</small></div></div><div className="severity-legend">{severityNames.map((severity, index) => <div className="severity-line" key={severity}><span><i style={{ background: severityColors[index] }} />{severity}</span><strong>{String(severityCounts[severity]).padStart(2, '0')}</strong></div>)}</div></div>
        <div className="panel-footnote"><span className="tiny-info">i</span> {isLive ? 'Counts from latest live scan' : isDemo ? 'Counts from illustrative Northstar demo' : 'No scan results yet'}</div>
      </article>
    </section>
  )
}