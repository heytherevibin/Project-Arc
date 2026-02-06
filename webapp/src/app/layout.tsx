'use client';

import '@ant-design/v5-patch-for-react-19';
import { Orbitron, JetBrains_Mono } from 'next/font/google';
import { ConfigProvider, App as AntApp } from 'antd';
import { createTheme } from '@/lib/theme';
import { StoreProvider } from '@/store/provider';
import { PageTransition } from '@/components/PageTransition';
import './globals.css';

const orbitron = Orbitron({
  subsets: ['latin'],
  variable: '--font-heading',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const theme = createTheme({
    fontHeading: orbitron.style.fontFamily,
    fontMono: jetbrainsMono.style.fontFamily,
  });

  return (
    <html lang="en" className={`${orbitron.variable} ${jetbrainsMono.variable}`}>
      <head>
        <title>Project ARC</title>
        <meta name="description" content="Enterprise Autonomous AI Red Team Framework" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </head>
      <body>
        <ConfigProvider theme={theme}>
          <AntApp>
            <StoreProvider>
              <PageTransition>{children}</PageTransition>
            </StoreProvider>
          </AntApp>
        </ConfigProvider>
      </body>
    </html>
  );
}
