export class ReplayCache {
  private store = new Map<string, number>();

  constructor(private ttlSeconds: number) {}

  private key(developerClientId: string, projectId: string, jti: string) {
    return `${developerClientId}:${projectId}:${jti}`;
  }

  public consume(developerClientId: string, projectId: string, jti: string): boolean {
    const now = Date.now();
    const key = this.key(developerClientId, projectId, jti);
    const expiresAt = this.store.get(key);
    if (expiresAt && expiresAt > now) {
      return false;
    }
    this.store.set(key, now + this.ttlSeconds * 1000);
    return true;
  }

  public sweep() {
    const now = Date.now();
    for (const [key, exp] of this.store.entries()) {
      if (exp <= now) {
        this.store.delete(key);
      }
    }
  }
}
