import { createContext, useContext, useEffect, useState, ReactNode } from 'react'

type ThemeMode = 'light' | 'dark' | 'system'

interface ThemeContextValue {
  mode: ThemeMode
  isDark: boolean
  cycle: () => void
}

const ThemeContext = createContext<ThemeContextValue>({ mode: 'system', isDark: false, cycle: () => {} })

const STORAGE_KEY = 'csf-theme'
const CYCLE_ORDER: ThemeMode[] = ['light', 'dark', 'system']

function getSystemDark() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

function resolveIsDark(mode: ThemeMode) {
  return mode === 'dark' || (mode === 'system' && getSystemDark())
}

function syncDarkClass(mode: ThemeMode) {
  const dark = resolveIsDark(mode)
  if (dark) {
    document.documentElement.classList.add('dark')
  } else {
    document.documentElement.classList.remove('dark')
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ThemeMode>(() => {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark' || stored === 'system') return stored
    return 'system'
  })

  // Apply dark class + persist on every mode change
  useEffect(() => {
    syncDarkClass(mode)
    localStorage.setItem(STORAGE_KEY, mode)
  }, [mode])

  // Listen for OS preference changes when in system mode
  useEffect(() => {
    if (mode !== 'system') return
    const mql = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = () => syncDarkClass('system')
    mql.addEventListener('change', handler)
    return () => mql.removeEventListener('change', handler)
  }, [mode])

  function cycle() {
    const next = CYCLE_ORDER[(CYCLE_ORDER.indexOf(mode) + 1) % CYCLE_ORDER.length]
    // Apply immediately — don't wait for React re-render + useEffect
    syncDarkClass(next)
    setMode(next)
  }

  const isDark = resolveIsDark(mode)

  return (
    <ThemeContext.Provider value={{ mode, isDark, cycle }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  return useContext(ThemeContext)
}
