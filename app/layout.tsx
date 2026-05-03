import type { Metadata, Viewport } from "next";
import "@/app/globals.css";

export const metadata: Metadata = {
  title: "FileSn4p | Secure File Transfer",
  description: "Encrypted, expiring file sharing for active recipients.",
  icons: {
    icon: "/favicon.svg"
  }
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#0b0f14" },
    { media: "(prefers-color-scheme: light)", color: "#f7f9fc" }
  ]
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{
          __html: `
            (function() {
              const saved = localStorage.getItem('filesn4p-theme');
              const theme = saved || 'dark';
              document.documentElement.dataset.theme = theme;
            })();
          `
        }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
