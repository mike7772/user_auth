
// extracts the token from the cookie string

export function getCookie(value: any, name: string) {
  const cookies = value.split("; ");
  for (const cookie of cookies) {
    const [cookieName, cookieValue] = cookie.split("=");
    if (cookieName === name) {
      return decodeURIComponent(cookieValue);
    }
  }
  return null; // Cookie not found
}
