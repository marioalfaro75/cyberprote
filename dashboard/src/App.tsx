import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import RiskOverview from './pages/RiskOverview'
import ToxicCombinations from './pages/ToxicCombinations'
import FindingsList from './pages/FindingsList'
import ConnectorHealth from './pages/ConnectorHealth'
import Policies from './pages/Policies'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<RiskOverview />} />
        <Route path="/toxic-combinations" element={<ToxicCombinations />} />
        <Route path="/findings" element={<FindingsList />} />
        <Route path="/connectors" element={<ConnectorHealth />} />
        <Route path="/policies" element={<Policies />} />
      </Routes>
    </Layout>
  )
}

export default App
