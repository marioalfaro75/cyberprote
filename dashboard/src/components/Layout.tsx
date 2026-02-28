import { Link, useLocation } from 'react-router-dom'
import { ReactNode } from 'react'

const navItems = [
  { path: '/', label: 'Risk Overview' },
  { path: '/toxic-combinations', label: 'Toxic Combinations' },
  { path: '/findings', label: 'Findings' },
  { path: '/connectors', label: 'Connectors' },
  { path: '/policies', label: 'Policies' },
]

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation()

  return (
    <div className="min-h-screen flex">
      <aside className="w-64 bg-gray-900 text-white p-4">
        <h1 className="text-xl font-bold mb-8">Cloud Security Fabric</h1>
        <nav className="space-y-2">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`block px-3 py-2 rounded ${
                location.pathname === item.path
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-300 hover:bg-gray-700'
              }`}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="flex-1 p-8">{children}</main>
    </div>
  )
}
