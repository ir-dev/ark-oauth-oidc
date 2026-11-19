import Providers from './providers';
import { ark } from '@/lib/ark';

export const metadata = { title: 'Ark Next.js example' };

// A server component may import the client too: creating it touches no browser API, and on the
// server its state is always `loading`.
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body data-ark-client={ark.clientId}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
