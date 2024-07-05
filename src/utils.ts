import { sessions } from "./login";
import crypto from 'crypto'
/**
 * This is a PRIVILEGED function and should only be called upon successful authentication.
 */
const SESSSION_TIMEOUT_EXPIRY = 6 * 3600 * 1000; // 6 hours

export const createSession = (username: string) => {
    if (!sessions.has(username)) sessions.set(username, new Set<string>());
    const sessionId = crypto.randomBytes(64).toString("hex");
    sessions.get(username)!.add(sessionId);

    // set a timeout to remove the session after the expiry time
    setTimeout(() => sessions.get(username)!.delete(sessionId), SESSSION_TIMEOUT_EXPIRY);

    return sessionId;
}