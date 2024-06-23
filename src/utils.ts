import { sessions } from "./login";
import crypto from 'crypto'
/**
 * This is a PRIVILEGED function and should only be called upon successful authentication.
 */
export const createSession = (username: string) => {
    if (!sessions.has(username)) sessions.set(username, []);
    const sessionId = crypto.randomBytes(64).toString("hex");
    sessions.get(username)!.push(sessionId);

    return sessionId;
}