import { Link, useLocation } from 'react-router-dom'
import { ReactNode } from 'react'
import { useTheme } from '../context/ThemeContext'

const navItems = [
  { path: '/', label: 'Risk Overview' },
  { path: '/compliance', label: 'Compliance' },
  { path: '/threat-intel', label: 'Threat Intel' },
  { path: '/toxic-combinations', label: 'Toxic Combinations' },
  { path: '/findings', label: 'Findings' },
  { path: '/connectors', label: 'Connectors' },
  { path: '/policies', label: 'Policies' },
]

const bottomNavItems = [
  { path: '/settings', label: 'Settings' },
]

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const { mode, isDark, cycle } = useTheme()

  const themeIcon = mode === 'light' ? (
    // Sun icon — currently light, click to go dark
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5">
      <path d="M10 2a.75.75 0 01.75.75v1.5a.75.75 0 01-1.5 0v-1.5A.75.75 0 0110 2zM10 15a.75.75 0 01.75.75v1.5a.75.75 0 01-1.5 0v-1.5A.75.75 0 0110 15zM10 7a3 3 0 100 6 3 3 0 000-6zM15.657 5.404a.75.75 0 10-1.06-1.06l-1.061 1.06a.75.75 0 001.06 1.06l1.06-1.06zM6.464 14.596a.75.75 0 10-1.06-1.06l-1.06 1.06a.75.75 0 001.06 1.06l1.06-1.06zM18 10a.75.75 0 01-.75.75h-1.5a.75.75 0 010-1.5h1.5A.75.75 0 0118 10zM5 10a.75.75 0 01-.75.75h-1.5a.75.75 0 010-1.5h1.5A.75.75 0 015 10zM14.596 15.657a.75.75 0 001.06-1.06l-1.06-1.061a.75.75 0 10-1.06 1.06l1.06 1.06zM5.404 6.464a.75.75 0 001.06-1.06l-1.06-1.06a.75.75 0 10-1.06 1.06l1.06 1.06z" />
    </svg>
  ) : mode === 'dark' ? (
    // Moon icon — currently dark, click to go system
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5">
      <path fillRule="evenodd" d="M7.455 2.004a.75.75 0 01.26.77 7 7 0 009.958 7.967.75.75 0 011.067.853A8.5 8.5 0 116.647 1.921a.75.75 0 01.808.083z" clipRule="evenodd" />
    </svg>
  ) : (
    // Monitor icon — currently system, click to go light
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5">
      <path fillRule="evenodd" d="M2 4.25A2.25 2.25 0 014.25 2h11.5A2.25 2.25 0 0118 4.25v8.5A2.25 2.25 0 0115.75 15h-3.105a3.501 3.501 0 001.1 1.677A.75.75 0 0113.26 18H6.74a.75.75 0 01-.484-1.323A3.501 3.501 0 007.355 15H4.25A2.25 2.25 0 012 12.75v-8.5zm1.5 0a.75.75 0 01.75-.75h11.5a.75.75 0 01.75.75v7.5a.75.75 0 01-.75.75H4.25a.75.75 0 01-.75-.75v-7.5z" clipRule="evenodd" />
    </svg>
  )

  const themeLabel = mode === 'light' ? 'Light' : mode === 'dark' ? 'Dark' : 'System'

  return (
    <div className="min-h-screen flex bg-gray-50 text-gray-900 dark:bg-gray-900 dark:text-gray-100">
      <aside className="w-64 shrink-0 bg-gray-900 text-white p-4 flex flex-col sticky top-0 h-screen overflow-y-auto">
        <h1 className="text-xl font-bold mb-8">Cloud Security Fabric</h1>
        <nav className="space-y-2 flex-1">
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
        <div className="border-t border-gray-700 pt-2 mt-2 space-y-2">
          {bottomNavItems.map((item) => (
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
        </div>
      </aside>
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="flex items-center justify-end gap-4 px-8 py-3 border-b border-gray-200 dark:border-gray-700">
          <button
            onClick={cycle}
            className="flex items-center gap-1.5 px-2 py-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 transition-colors"
            title={`Theme: ${themeLabel}`}
          >
            {themeIcon}
            <span className="text-xs">{themeLabel}</span>
          </button>
        </header>
        <main className="flex-1 overflow-x-auto p-8">{children}</main>
      </div>
    </div>
  )
}
