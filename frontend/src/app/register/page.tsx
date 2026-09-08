"use client";

import { useRouter } from "next/navigation";
import RegisterForm from "@/components/auth/RegisterForm";

export default function RegisterPage() {
  const router = useRouter();

  function handleSuccess() {
    router.push("/dashboard");
  }

  return (
    <main className="auth-shell">
      <RegisterForm onSuccess={handleSuccess} />
    </main>
  );
}
