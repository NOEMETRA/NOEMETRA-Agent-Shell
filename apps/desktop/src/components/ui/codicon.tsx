import type { Icon } from '@tabler/icons-react'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  AppWindow,
  Archive,
  ArrowDown,
  ArrowLeft,
  ArrowLeftRight,
  ArrowRight,
  ArrowUp,
  ArrowUpRight,
  AudioLines,
  BadgeCheck,
  BarChart3,
  Bell,
  Blocks,
  BookOpen,
  Bot,
  Braces,
  Bug,
  Building2,
  Calendar,
  Camera,
  Check,
  CheckCheck,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsDownUp,
  Circle,
  CircleCheck,
  Clock,
  CloudDownload,
  CloudUpload,
  Columns2,
  Compass,
  Copy,
  Cpu,
  CreditCard,
  Crosshair,
  ExternalLink,
  Eye,
  EyeOff,
  File,
  FileDiff,
  FilePlus,
  Files,
  Filter,
  Folder,
  FolderGit2,
  FolderOpen,
  FolderPlus,
  FolderRoot,
  GitBranch,
  GitPullRequest,
  Globe,
  GripVertical,
  Headphones,
  HelpCircle,
  Home,
  Image,
  Inbox,
  Kanban,
  Keyboard,
  Laptop,
  Layers,
  Library,
  List,
  ListChecks,
  ListFilter,
  Loader2,
  type LucideIcon,
  MessageSquare,
  MessagesSquare,
  Mic,
  Minimize2,
  Minus,
  Monitor,
  MoreHorizontal,
  MoreVertical,
  Package,
  Palette,
  Paperclip,
  Pause,
  Pencil,
  Pin,
  PinOff,
  Play,
  PlayCircle,
  Plus,
  RefreshCw,
  Reply,
  RotateCcw,
  Save,
  Send,
  Settings,
  ShieldCheck,
  Sliders,
  Smile,
  Sparkles,
  Square,
  Star,
  StepForward,
  StopCircle,
  Terminal,
  Trash2,
  Type,
  Undo2,
  Unplug,
  User,
  VolumeX,
  Wrench,
  X,
  Zap
} from 'lucide-react'
import type * as React from 'react'

import { cn } from '@/lib/utils'

const LUCIDE_BY_CODICON: Record<string, LucideIcon> = {
  account: User,
  add: Plus,
  agent: Cpu,
  archive: Archive,
  'arrow-down': ArrowDown,
  'arrow-left': ArrowLeft,
  'arrow-right': ArrowRight,
  'arrow-small-right': ArrowRight,
  'arrow-swap': ArrowLeftRight,
  'arrow-up': ArrowUp,
  'arrow-up-right': ArrowUpRight,
  attach: Paperclip,
  'audio-lines': AudioLines,
  bell: Bell,
  book: BookOpen,
  bug: Bug,
  calendar: Calendar,
  check: Check,
  'check-all': CheckCheck,
  checklist: ListChecks,
  'chevron-down': ChevronDown,
  'chevron-left': ChevronLeft,
  'chevron-right': ChevronRight,
  chip: Cpu,
  'chrome-close': X,
  'chrome-minimize': Minus,
  'circle-outline': Circle,
  close: X,
  'cloud-download': CloudDownload,
  'cloud-upload': CloudUpload,
  'collapse-all': ChevronsDownUp,
  comment: MessageSquare,
  'comment-discussion': MessagesSquare,
  compass: Compass,
  copy: Copy,
  'credit-card': CreditCard,
  dash: Minus,
  'debug-breakpoint-data-unverified': AlertCircle,
  'debug-continue': Play,
  'debug-disconnect': Unplug,
  'debug-pause': Pause,
  'debug-restart': RotateCcw,
  'debug-step-over': StepForward,
  'debug-stop': Square,
  'device-camera': Camera,
  'device-desktop': Monitor,
  diff: FileDiff,
  'diff-added': FilePlus,
  discard: Undo2,
  edit: Pencil,
  ellipsis: MoreHorizontal,
  'empty-window': AppWindow,
  error: AlertCircle,
  extensions: Blocks,
  eye: Eye,
  'eye-closed': EyeOff,
  file: File,
  'file-media': Image,
  files: Files,
  filter: Filter,
  folder: Folder,
  'folder-opened': FolderOpen,
  gear: Settings,
  'git-branch': GitBranch,
  'git-pull-request': GitPullRequest,
  globe: Globe,
  graph: BarChart3,
  gripper: GripVertical,
  headphones: Headphones,
  home: Home,
  hubot: Bot,
  inbox: Inbox,
  json: Braces,
  'kebab-vertical': MoreVertical,
  layers: Layers,
  library: Library,
  'link-external': ExternalLink,
  'list-filter': ListFilter,
  'list-selection': ListChecks,
  'list-unordered': List,
  loading: Loader2,
  mic: Mic,
  'mic-filled': Mic,
  mute: VolumeX,
  'new-folder': FolderPlus,
  organization: Building2,
  package: Package,
  pass: CircleCheck,
  'pass-filled': CheckCircle2,
  pin: Pin,
  pinned: PinOff,
  play: Play,
  'play-circle': PlayCircle,
  project: Kanban,
  pulse: Activity,
  question: HelpCircle,
  'record-keys': Keyboard,
  refresh: RefreshCw,
  remote: Laptop,
  reply: Reply,
  repo: FolderGit2,
  robot: Bot,
  'root-folder': FolderRoot,
  save: Save,
  'screen-normal': Minimize2,
  send: Send,
  'settings-gear': Settings,
  'shield-check': ShieldCheck,
  smiley: Smile,
  sparkle: Sparkles,
  'split-horizontal': Columns2,
  'star-full': Star,
  'stop-circle': StopCircle,
  'symbol-color': Palette,
  'symbol-misc': Sparkles,
  sync: RefreshCw,
  target: Crosshair,
  terminal: Terminal,
  'text-size': Type,
  tools: Wrench,
  trash: Trash2,
  'verified-filled': BadgeCheck,
  warning: AlertTriangle,
  watch: Clock,
  zap: Zap
}

const FILLED_ICONS = new Set(['star-full', 'mic-filled', 'pass-filled', 'verified-filled'])
const SPINNING_BY_DEFAULT = new Set(['loading'])

export interface CodiconProps extends React.HTMLAttributes<HTMLElement> {
  name: string
  size?: number | string
  spinning?: boolean
}

export function Codicon({ className, name, size, spinning, style, ...props }: CodiconProps) {
  const IconComponent = LUCIDE_BY_CODICON[name]
  const isSpinning = spinning || SPINNING_BY_DEFAULT.has(name)

  if (IconComponent) {
    const isFilled = FILLED_ICONS.has(name)
    return (
      <IconComponent
        aria-hidden="true"
        className={cn('codicon', `codicon-${name}`, isSpinning && 'animate-spin', className)}
        fill={isFilled ? 'currentColor' : 'none'}
        size="1em"
        strokeWidth={name === 'star-full' ? 1.5 : 1.75}
        style={{
          ...(size != null && size !== '' ? { fontSize: size } : {}),
          ...(isFilled && name !== 'mic-filled' ? { fillOpacity: 0.18 } : {}),
          ...style
        }}
        {...(props as React.SVGAttributes<SVGSVGElement>)}
      />
    )
  }

  return (
    <i
      aria-hidden="true"
      className={cn('codicon', `codicon-${name}`, isSpinning && 'codicon-modifier-spin', className)}
      style={{ ...(size != null && size !== '' ? { fontSize: size } : {}), ...style }}
      {...props}
    />
  )
}

/** Wrap a codicon as a Tabler-shaped icon for nav rows that expect `IconComponent`. */
export function codiconIcon(name: string): Icon {
  function CodiconIcon({ className }: { className?: string }) {
    return <Codicon aria-hidden className={cn('leading-none', className)} name={name} size="1em" />
  }

  CodiconIcon.displayName = `Codicon(${name})`

  return CodiconIcon as Icon
}
