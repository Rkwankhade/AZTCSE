import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AZTCSE',
  description: 'Autonomous Zero-Trust Cloud Security Engine',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
