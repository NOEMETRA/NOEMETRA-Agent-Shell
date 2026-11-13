import { cn } from '@/lib/utils'

const assetPath = (path: string) => `${import.meta.env.BASE_URL}${path.replace(/^\/+/, '')}`

// Brand badge: the NOEMETRA neural-prism mark in the app-icon squircle.
export function BrandMark({ className, ...props }: React.ComponentProps<'span'>) {
  return (
    <span className={cn('inline-flex size-14 shrink-0 items-center justify-center', className)} {...props}>
      <img alt="NOEMETRA" className="size-full object-contain" src={assetPath('noemetra-mark.png')} />
    </span>
  )
}
