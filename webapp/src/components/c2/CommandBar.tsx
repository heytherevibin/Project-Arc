'use client';

export interface CommandBarProps {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export function CommandBar({ children, className, style }: CommandBarProps) {
  return (
    <div className={`c2-command-bar ${className ?? ''}`.trim()} style={style}>
      {children}
    </div>
  );
}
