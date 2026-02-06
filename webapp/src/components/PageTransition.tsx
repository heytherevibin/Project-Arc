'use client';

import { useEffect, type ReactNode } from 'react';
import { message } from 'antd';

/**
 * Wraps app content to configure message (toast) settings.
 * Note: Removed key={pathname} which was causing full remounts on navigation.
 */
export function PageTransition({ children }: { children: ReactNode }) {
  useEffect(() => {
    message.config({
      duration: 3,
      maxCount: 3,
    });
  }, []);

  return (
    <div className="page-transition">
      {children}
    </div>
  );
}
