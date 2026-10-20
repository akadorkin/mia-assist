/** «fetch failed» says nothing: the reason is in the cause (DNS, refused, TLS, timeout). */
export function why(e: unknown): string {
    const err = e as Error & { cause?: { code?: string; message?: string; hostname?: string } };
    const code = err.cause?.code;
    const ru: Record<string, string> = {
        ENOTFOUND: 'имя не резолвится',
        ECONNREFUSED: 'соединение отклонено',
        ETIMEDOUT: 'таймаут',
        UND_ERR_CONNECT_TIMEOUT: 'таймаут подключения',
        CERT_HAS_EXPIRED: 'сертификат истёк',
        DEPTH_ZERO_SELF_SIGNED_CERT: 'самоподписанный сертификат',
        ECONNRESET: 'соединение сброшено',
    };
    if (err.name === 'TimeoutError') return 'нет ответа за 20 с';
    if (err.message === 'fetch failed' && err.cause) return `не подключиться: ${(code && ru[code]) ?? err.cause.message ?? code}${err.cause.hostname ? ` (${err.cause.hostname})` : ''}`;
    return err.message;
}
