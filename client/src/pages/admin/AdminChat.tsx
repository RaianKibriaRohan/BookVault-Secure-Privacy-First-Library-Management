import { ChatSurface } from '../Chat'

export default function AdminChat() {
  return (
    <ChatSurface
      title="Patron messages"
      subtitle="Book requests, damaged copies and account questions. Each message is encrypted under your RSA public key — the server stored it without ever being able to read it."
    />
  )
}
