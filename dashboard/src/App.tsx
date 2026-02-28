import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import RiskOverview from './pages/RiskOverview'
import CompliancePosture from './pages/CompliancePosture'
import ToxicCombinations from './pages/ToxicCombinations'
import FindingsList from './pages/FindingsList'
import ConnectorHealth from './pages/ConnectorHealth'
import Policies from './pages/Policies'
import Settings from './pages/Settings'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<RiskOverview />} />
        <Route path="/compliance" element={<CompliancePosture />} />
        <Route path="/toxic-combinations" element={<ToxicCombinations />} />
        <Route path="/findings" element={<FindingsList />} />
        <Route path="/connectors" element={<ConnectorHealth />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  )
}

export default App
