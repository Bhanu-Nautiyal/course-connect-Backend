import "./globals.css";
import SmoothScroll from './/components/SmoothScroll';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
      <SmoothScroll>
        {children}
        </SmoothScroll>
      </body>
    </html>
  );
}