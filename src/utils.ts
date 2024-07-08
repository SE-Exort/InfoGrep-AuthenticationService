import { sessions } from "./login";
import crypto from 'crypto'
/**
 * This is a PRIVILEGED function and should only be called upon successful authentication.
 */
const SESSSION_TIMEOUT_EXPIRY = 6 * 3600 * 1000; // 6 hours

export const createSession = (userId: string) => {
    if (!sessions.has(userId)) sessions.set(userId, new Set<string>());
    const sessionId = crypto.randomBytes(64).toString("hex");
    sessions.get(userId)!.add(sessionId);

    // set a timeout to remove the session after the expiry time
    setTimeout(() => sessions.get(userId)!.delete(sessionId), SESSSION_TIMEOUT_EXPIRY);

    return sessionId;
}