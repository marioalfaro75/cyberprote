export interface PostureStatus {
  pass: number
  fail: number
  unknown: number
}

export interface FindingRef {
  uid: string
  title: string
  severity_id: number
  compliance_status: string
  provider: string
}

export interface ControlPosture {
  id: string
  name: string
  status: PostureStatus
  findings?: FindingRef[]
}

export interface CategoryPosture {
  id: string
  name: string
  status: PostureStatus
  controls: ControlPosture[]
}

export interface FunctionPosture {
  id: string
  name: string
  status: PostureStatus
  categories: CategoryPosture[]
}

export interface FrameworkPosture {
  framework_id: string
  name: string
  version: string
  score: number
  status: PostureStatus
  functions: FunctionPosture[]
}

export interface FrameworkSummary {
  framework_id: string
  name: string
  version: string
  score: number
  status: PostureStatus
}

export interface FrameworkInfo {
  id: string
  name: string
  version: string
}
