"use client";

import { useRouter } from "next/navigation";
import LoginForm from "@/components/auth/LoginForm";

export default function LoginPage() {
  const router = useRouter();

  function handleSuccess() {
    router.push("/dashboard");
  }

  return (
    <main className="auth-shell">
      <LoginForm onSuccess={handleSuccess} />
    </main>
  );
}
