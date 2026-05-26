import { redirect } from 'next/navigation'

/**
 * Root page — redirect unauthenticated visitors to the admin login page.
 * The admin panel is the only entry point for this application.
 */
export default function RootPage() {
  redirect('/admin')
}
