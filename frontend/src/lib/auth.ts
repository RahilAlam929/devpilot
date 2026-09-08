/**
 * Auth utilities.
 * These helpers call the API client and never touch localStorage/sessionStorage.
 * Auth state is derived entirely from the HttpOnly cookie managed by the backend.
 */

import { auth, ApiError, type User } from "./api";

/**
 * Returns the current user if the session cookie is valid, or null otherwise.
 * A 401 response means no active session — that is not an error.
 */
export async function getCurrentUser(): Promise<User | null> {
  try {
    return await auth.me();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return null;
    }
    throw err;
  }
}

/**
 * Attempt login; returns the authenticated user on success.
 * Throws ApiError on failure (wrong credentials, network, etc.)
 */
export async function login(email: string, password: string): Promise<User> {
  return auth.login(email, password);
}

/**
 * Attempt registration; returns the new user on success.
 * Throws ApiError on failure (duplicate email, weak password, etc.)
 */
export async function register(
  name: string,
  email: string,
  password: string,
): Promise<User> {
  return auth.register(name, email, password);
}

/**
 * Log out the current user. The backend clears the cookie.
 */
export async function logout(): Promise<void> {
  return auth.logout();
}

/**
 * Derive user initials for the avatar from name or email.
 */
export function userInitials(user: User): string {
  if (user.name) {
    return user.name
      .split(" ")
      .map((part) => part[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  }
  return user.email.slice(0, 2).toUpperCase();
}
